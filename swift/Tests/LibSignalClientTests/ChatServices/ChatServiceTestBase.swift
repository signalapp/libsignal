//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class ChatServiceTestBase<Selector: ServiceSelector>: TestCaseBase
where Selector.Api: Sendable, Selector.Connection: ChatServiceTestSetup {
    typealias SelectorCheck = Selector
    class var selector: SelectorCheck! { nil }

    override class func setUp() {
        super.setUp()
        precondition(self.selector != nil, "must override the selector property")
    }

    // XCTestCase does unusual things with its initializers for test case discovery,
    // so we can't override init(). Instead, we'll put our shared state in a helper type.
    // We specifically hide this to force tests to use the limited set of APIs in ``api``.
    private lazy var state: ChatServiceTestState<Selector.Connection> = .init(grpcOverrides: self.grpcOverrides)

    internal var api: Selector.Api {
        // swiftlint:disable:next force_cast
        state.connection as! Selector.Api
    }
    internal var fakeRemote: FakeChatRemote {
        state.fakeRemote
    }

    internal var grpcOverrides: [String] {
        []
    }
}

class UnauthChatServiceTestBase<Service: Sendable>: ChatServiceTestBase<UnauthServiceSelectorHelper<Service>> {}
class AuthChatServiceTestBase<Service: Sendable>: ChatServiceTestBase<AuthServiceSelectorHelper<Service>> {}

// Defined outside ChatServiceTestBase because it's not generic over the service.
private struct ChatServiceTestState<Connection: ChatServiceTestSetup> {
    let tokioAsyncContext = TokioAsyncContext()
    let connection: Connection.StaticSelf
    let fakeRemote: FakeChatRemote

    init(grpcOverrides: [String]) {
        (connection, fakeRemote) =
            Connection
            .fakeConnectWithNoOpListener(tokioAsyncContext: tokioAsyncContext, grpcOverrides: grpcOverrides)
    }
}

/// Helper protocol for fake connections with no-op listeners
protocol ChatServiceTestSetup {
    /// Avoids the restriction of `Self` being interpreted as a dynamic type.
    ///
    /// This syntax permits implementers to override the type; we will just never do that.
    associatedtype StaticSelf = Self
    static func fakeConnectWithNoOpListener(
        tokioAsyncContext: TokioAsyncContext,
        grpcOverrides: [String]
    ) -> (StaticSelf, FakeChatRemote)
}

extension UnauthenticatedChatConnection: ChatServiceTestSetup {
    static func fakeConnectWithNoOpListener(
        tokioAsyncContext: TokioAsyncContext,
        grpcOverrides: [String]
    ) -> (StaticSelf, FakeChatRemote) {
        class NoOpListener: ConnectionEventsListener {
            func connectionWasInterrupted(_ service: UnauthenticatedChatConnection, error: Error?) {}
        }

        return fakeConnect(
            tokioAsyncContext: tokioAsyncContext,
            listener: NoOpListener(),
            grpcOverrides: grpcOverrides,
        )
    }
}

extension AuthenticatedChatConnection: ChatServiceTestSetup {
    static func fakeConnectWithNoOpListener(
        tokioAsyncContext: TokioAsyncContext,
        grpcOverrides: [String]
    ) -> (StaticSelf, FakeChatRemote) {
        class NoOpListener: ChatConnectionListener {
            func connectionWasInterrupted(_ service: LibSignalClient.AuthenticatedChatConnection, error: (any Error)?) {
            }

            func chatConnection(
                _ chat: AuthenticatedChatConnection,
                didReceiveIncomingMessage envelope: Data,
                serverDeliveryTimestamp: UInt64,
                sendAck: @escaping () throws -> Void
            ) {}
            func chatConnectionDidReceiveQueueEmpty(_ chat: AuthenticatedChatConnection) {}
            func chatConnection(_ chat: AuthenticatedChatConnection, didReceiveAlerts alerts: [String]) {}
        }

        return fakeConnect(
            tokioAsyncContext: tokioAsyncContext,
            listener: NoOpListener(),
            grpcOverrides: grpcOverrides,
        )
    }
}

extension ChatServiceTestBase {
    func testSimpleGrpcRequest<Result>(
        requestName: String,
        expectedRequest: NSDictionary,
        responseName: String,
        response: NSDictionary,
        sendRequest: @Sendable (Selector.Api) async throws -> Result,
    ) async throws -> Result {
        signal_testing_enable_deterministic_rng_for_testing()

        let api = self.api
        async let result = sendRequest(api)

        let (request, id) = try await fakeRemote.getNextIncomingGrpcRequest()
        XCTAssertEqual(request.getSingleGrpcMessage(requestName), expectedRequest)
        try await fakeRemote.sendGrpcResponse(requestId: id, name: responseName, json: response)

        return try await result
    }
    func testGrpcCases<Args: Sendable, Out, T>(
        _ tests: [GrpcTestCase<Args, Out>],
        invoke: @Sendable (Selector.Api, Args) async throws -> T,
        check: (Out, Result<T, any Error>) throws -> Void,
    ) async throws
    where Args: Sendable {
        for test in tests {
            let api = self.api
            let requestInfo = test.request
            async let resultFuture = invoke(api, requestInfo)
            let (request, id) = try await fakeRemote.getNextIncomingGrpcRequest()
            XCTAssertEqual(request.getSingleGrpcMessageData(), test.requestGrpc)
            XCTAssertEqual(request.pathAndQuery, test.method)
            try await fakeRemote.sendGrpcResponse(requestId: id, ChatResponse(status: 200, body: test.responseGrpc))
            let result: Result<T, any Error>
            do {
                result = .success(try await resultFuture)
            } catch {
                result = .failure(error)
            }
            try check(test.response, result)
        }
    }
}

internal struct GrpcTestCase<Req, Resp> {
    let name: String
    let method: String
    let request: Req
    let requestGrpc: Data
    let responseGrpc: Data
    let response: Resp
}

internal enum UneraseType<Converter: NiceReturnConverter> {
    static func convertReturn(consuming value: SignalFfiErasedForTesting) throws -> Converter.NiceReturn {
        defer { value.destroy(value.contents) }
        let loaded = value.contents.load(as: Converter.FfiReturn.self)
        return try Converter.convertReturn(consuming: loaded)
    }
}

internal enum GrpcTestCaseVecConverter<
    ReqConverter: NiceReturnConverter,
    RespConverter: NiceReturnConverter,
>: NiceReturnConverter {
    typealias NiceReturn = [GrpcTestCase<ReqConverter.NiceReturn, RespConverter.NiceReturn>]

    typealias FfiReturn = SignalOwnedBufferOfGrpcTestCaseBridgedFfi

    static func emptyFfiReturn() -> FfiReturn {
        FfiReturn()
    }

    static func convertReturn(consuming value: FfiReturn) throws -> NiceReturn {
        // Since this is just used in testing, we won't worry about leaking memory on error.
        defer { signal_free_testing_signle_grpc_testing_bridged_vec(value) }
        return try UnsafeBufferPointer<SignalGrpcTestCaseBridgedFfi>(start: value.base, count: value.length).map {
            it in
            GrpcTestCase(
                name: try StringConverter.convertReturn(consuming: it.name),
                method: try StringConverter.convertReturn(consuming: it.method),
                request: try UneraseType<ReqConverter>.convertReturn(consuming: it.request),
                requestGrpc: try DataConverter.convertReturn(consuming: it.request_grpc),
                responseGrpc: try DataConverter.convertReturn(consuming: it.response_grpc),
                response: try UneraseType<RespConverter>.convertReturn(consuming: it.response),
            )
        }
    }
}

#endif

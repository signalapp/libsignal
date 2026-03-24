//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

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
    private let state: ChatServiceTestState<Selector.Connection> = .init()

    internal var api: Selector.Api {
        // swiftlint:disable:next force_cast
        state.connection as! Selector.Api
    }
    internal var fakeRemote: FakeChatRemote {
        state.fakeRemote
    }
}

class UnauthChatServiceTestBase<Service: Sendable>: ChatServiceTestBase<UnauthServiceSelectorHelper<Service>> {}
class AuthChatServiceTestBase<Service: Sendable>: ChatServiceTestBase<AuthServiceSelectorHelper<Service>> {}

// Defined outside ChatServiceTestBase because it's not generic over the service.
private struct ChatServiceTestState<Connection: ChatServiceTestSetup> {
    let tokioAsyncContext = TokioAsyncContext()
    let connection: Connection.StaticSelf
    let fakeRemote: FakeChatRemote

    init() {
        (connection, fakeRemote) = Connection.fakeConnectWithNoOpListener(tokioAsyncContext: tokioAsyncContext)
    }
}

/// Helper protocol for fake connections with no-op listeners
protocol ChatServiceTestSetup {
    /// Avoids the restriction of `Self` being interpreted as a dynamic type.
    ///
    /// This syntax permits implementers to override the type; we will just never do that.
    associatedtype StaticSelf = Self
    static func fakeConnectWithNoOpListener(tokioAsyncContext: TokioAsyncContext) -> (StaticSelf, FakeChatRemote)
}

extension UnauthenticatedChatConnection: ChatServiceTestSetup {
    static func fakeConnectWithNoOpListener(tokioAsyncContext: TokioAsyncContext) -> (StaticSelf, FakeChatRemote) {
        class NoOpListener: ConnectionEventsListener {
            func connectionWasInterrupted(_ service: UnauthenticatedChatConnection, error: Error?) {}
        }

        return fakeConnect(
            tokioAsyncContext: tokioAsyncContext,
            listener: NoOpListener()
        )
    }
}

extension AuthenticatedChatConnection: ChatServiceTestSetup {
    static func fakeConnectWithNoOpListener(tokioAsyncContext: TokioAsyncContext) -> (StaticSelf, FakeChatRemote) {
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
            listener: NoOpListener()
        )
    }
}

#endif

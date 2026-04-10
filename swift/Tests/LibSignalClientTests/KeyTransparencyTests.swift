//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi
import XCTest

@testable import LibSignalClient

class TestStore: KeyTransparency.Store {
    var distinguishedTreeHeads: [Data] = []
    var accountData: [Aci: [Data]] = [:]

    func getLastDistinguishedTreeHead() async -> Data? {
        return self.distinguishedTreeHeads.last
    }

    func setLastDistinguishedTreeHead(to data: Data) async {
        self.distinguishedTreeHeads.append(data)
    }

    func getAccountData(for aci: Aci) async -> Data? {
        return self.accountData[aci]?.last
    }

    func setAccountData(_ data: Data, for aci: Aci) async {
        self.accountData[aci, default: []].append(data)
    }
}

struct TestAccount {
    let aci: Aci
    let identityKey: IdentityKey
    let e164: String
    let unidentifiedAccessKey: Data
    let usernameHash: Data
}

extension TestAccount {
    var aciInfo: KeyTransparency.AciInfo {
        return KeyTransparency.AciInfo(
            aci: self.aci,
            identityKey: self.identityKey
        )
    }

    var e164Info: KeyTransparency.E164Info {
        return KeyTransparency.E164Info(
            e164: self.e164,
            unidentifiedAccessKey: self.unidentifiedAccessKey
        )
    }
}

final class KeyTransparencyTests: TestCaseBase {
    private let userAgent = "kt-test"

    override func nonHermeticTest() throws {
        if ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_IGNORE_KT_TESTS"] != nil {
            throw XCTSkip("disabled via LIBSIGNAL_TESTING_IGNORE_KT_TESTS")
        }
        try super.nonHermeticTest()
    }

    private var testAccount = TestAccount(
        aci: Aci(fromUUID: UUID(uuidString: "90c979fd-eab4-4a08-b6da-69dedeab9b29")!),
        identityKey: try! IdentityKey(
            bytes: [UInt8](fromHexString: "05cdcbb178067f0ddfd258bb21d006e0aa9c7ab132d9fb5e8b027de07d947f9d0c")!
        ),
        e164: "+18005550100",
        unidentifiedAccessKey: Data(fromHexString: "108d84b71be307bdf101e380a1d7f2a2")!,
        usernameHash: Data(
            fromHexString:
                "dc711808c2cf66d5e6a33ce41f27d69d942d2e1ff4db22d39b42d2eff8d09746"
        )!
    )

    private class NoOpListener: ConnectionEventsListener {
        func connectionWasInterrupted(_: UnauthenticatedChatConnection, error: Error?) {}
    }

    func testCheck() async throws {
        try self.nonHermeticTest()

        let net = Net(env: .staging, userAgent: userAgent, buildVariant: .production)
        let chat = try await net.connectUnauthenticatedChat()
        chat.start(listener: NoOpListener())
        let store = TestStore()

        // First check will perform the initial search is required prior to
        // monitor to populate the account data in the store
        try await chat.keyTransparencyClient.check(
            for: .contact,
            account: self.testAccount.aciInfo,
            e164: self.testAccount.e164Info,
            store: store
        )
        XCTAssertEqual(1, store.accountData[self.testAccount.aci]!.count)
        XCTAssertEqual(1, store.distinguishedTreeHeads.count)

        try await chat.keyTransparencyClient.check(
            for: .contact,
            account: self.testAccount.aciInfo,
            e164: self.testAccount.e164Info,
            store: store
        )
        // Second check will send a monitor request, and should update account
        // data in store, but the distinguished tree should have been reused
        // and not updated
        XCTAssertEqual(2, store.accountData[self.testAccount.aci]!.count)
        XCTAssertEqual(1, store.distinguishedTreeHeads.count)
    }

    // These testing endpoints aren't generated in device builds, to save on code size.
    #if !os(iOS) || targetEnvironment(simulator)
    func testNonFatalErrorBridging() throws {
        do {
            try checkError(signal_testing_key_trans_non_fatal_verification_failure())
            XCTFail("should have failed")
        } catch SignalError.keyTransparencyError(_) {
        } catch {
            XCTFail("unexpected exception thrown: \(error)")
        }
    }

    func testFatalErrorBridging() throws {
        do {
            try checkError(signal_testing_key_trans_fatal_verification_failure())
            XCTFail("should have failed")
        } catch SignalError.keyTransparencyVerificationFailed(_) {
        } catch {
            XCTFail("unexpected exception thrown: \(error)")
        }
    }

    func testChatSendErrorBridging() throws {
        do {
            try checkError(signal_testing_key_trans_chat_send_error())
            XCTFail("should have failed")
        } catch SignalError.requestTimeoutError(_) {
        } catch {
            XCTFail("unexpected exception thrown: \(error)")
        }
    }

    func customNetworkErrorTestImpl(status: UInt16, headers: [String: String] = [:]) async throws {
        let tokio = TokioAsyncContext()
        let (chat, remote) = UnauthenticatedChatConnection.fakeConnect(
            tokioAsyncContext: tokio,
            listener: NoOpListener()
        )
        defer { withExtendedLifetime(chat) {} }

        let store = TestStore()
        let aciInfo = self.testAccount.aciInfo
        async let future: () = chat.keyTransparencyClient.check(
            for: .contact,
            account: aciInfo,
            store: store
        )

        let (_, id) = try await remote.getNextIncomingRequest()

        try remote.sendResponse(requestId: id, ChatResponse(status: status, headers: headers))
        _ = try await future
    }

    func testRetryAfter() async throws {
        do {
            try await customNetworkErrorTestImpl(status: 429, headers: ["retry-after": "42"])
            XCTFail("should have failed")
        } catch SignalError.rateLimitedError(_, _) {
        } catch {
            XCTFail("Unexpected exception thrown: \(error)")
        }
    }

    func testUnexpectedRetryAfter() async throws {
        do {
            // 429 without retry-after header is unexpected
            try await customNetworkErrorTestImpl(status: 429)
            XCTFail("should have failed")
        } catch SignalError.networkProtocolError(_) {
        } catch {
            XCTFail("Unexpected exception thrown: \(error)")
        }
    }

    func testServerError() async throws {
        do {
            try await customNetworkErrorTestImpl(status: 500)
            XCTFail("should have failed")
        } catch SignalError.ioError(_) {
        } catch {
            XCTFail("Unexpected exception thrown: \(error)")
        }
    }

    #endif
}

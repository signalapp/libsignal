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

    private var testAccount = TestAccount(
        aci: Aci(fromUUID: UUID(uuidString: "90c979fd-eab4-4a08-b6da-69dedeab9b29")!),
        identityKey: try! IdentityKey(
            bytes: [UInt8](fromHexString: "05111f9464c1822c6a2405acf1c5a4366679dc3349fc8eb015c8d7260e3f771177")!
        ),
        e164: "+18005550100",
        unidentifiedAccessKey: Data(fromHexString: "c6f7c258c24d69538ea553b4a943c8d9")!,
        usernameHash: Data(
            fromHexString:
                "d237a4b83b463ca7da58d4a16bf6a3ba104506eb412b235eb603ea10f467c655"
        )!
    )

    private class NoOpListener: ConnectionEventsListener {
        func connectionWasInterrupted(_: UnauthenticatedChatConnection, error: Error?) {}
    }

    func testUnknownDistinguished() async throws {
        try self.nonHermeticTest()

        let net = Net(env: .staging, userAgent: userAgent)
        let chat = try await net.connectUnauthenticatedChat()
        chat.start(listener: NoOpListener())

        XCTAssertNoThrow { try await chat.keyTransparencyClient.getDistinguished() }
    }

    func testSearch() async throws {
        try self.nonHermeticTest()

        let net = Net(env: .staging, userAgent: userAgent)
        let chat = try await net.connectUnauthenticatedChat()
        chat.start(listener: NoOpListener())
        let store = TestStore()

        let before = await store.getAccountData(for: self.testAccount.aci)
        XCTAssertNil(before)
        try await chat.keyTransparencyClient.search(
            account: self.testAccount.aciInfo,
            e164: self.testAccount.e164Info,
            store: store
        )
        let after = await store.getAccountData(for: self.testAccount.aci)
        XCTAssertNotNil(after)
    }

    func testMonitor() async throws {
        try self.nonHermeticTest()

        let net = Net(env: .staging, userAgent: userAgent)
        let chat = try await net.connectUnauthenticatedChat()
        chat.start(listener: NoOpListener())
        let store = TestStore()

        // Initial search is required prior to monitor to populate
        // the account data in the store
        try await chat.keyTransparencyClient.search(
            account: self.testAccount.aciInfo,
            e164: self.testAccount.e164Info,
            store: store
        )
        XCTAssertEqual(1, store.accountData[self.testAccount.aci]!.count)
        try await chat.keyTransparencyClient.monitor(
            for: .self,
            account: self.testAccount.aciInfo,
            e164: self.testAccount.e164Info,
            store: store
        )
        // Successful monitor request should update account data in store
        XCTAssertEqual(2, store.accountData[self.testAccount.aci]!.count)
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
    #endif
}

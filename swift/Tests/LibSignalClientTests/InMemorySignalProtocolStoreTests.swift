//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

class InMemorySignalProtocolStoreTests: TestCaseBase {
    func testInMemoryIdentityKeyStore() throws {
        let store = InMemorySignalProtocolStore()
        let context = NullContext()

        let address = try ProtocolAddress(name: "address", deviceId: 12)
        XCTAssertNil(try store.identity(for: address, context: context))

        let firstIdentity = IdentityKeyPair.generate().identityKey
        XCTAssert(
            try store.isTrustedIdentity(firstIdentity, for: address, direction: .sending, context: context)
        )

        XCTAssertEqual(
            try store.saveIdentity(firstIdentity, for: address, context: context),
            .newOrUnchanged
        )
        // Idempotent
        XCTAssertEqual(
            try store.saveIdentity(firstIdentity, for: address, context: context),
            .newOrUnchanged
        )
        XCTAssert(try store.isTrustedIdentity(firstIdentity, for: address, direction: .sending, context: context))
        XCTAssertEqual(try store.identity(for: address, context: context), firstIdentity)

        let secondIdentity = IdentityKeyPair.generate().identityKey

        XCTAssertFalse(
            try store.isTrustedIdentity(secondIdentity, for: address, direction: .sending, context: context)
        )
        XCTAssertEqual(
            try store.saveIdentity(secondIdentity, for: address, context: context),
            .replacedExisting
        )
        // Idempotent
        XCTAssertEqual(
            try store.saveIdentity(secondIdentity, for: address, context: context),
            .newOrUnchanged
        )

        XCTAssert(
            try store.isTrustedIdentity(secondIdentity, for: address, direction: .sending, context: context)
        )
        XCTAssertEqual(try store.identity(for: address, context: context), secondIdentity)
    }
}

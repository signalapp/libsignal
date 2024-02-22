//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

@testable import LibSignalClient
import XCTest

class BadStore: InMemorySignalProtocolStore {
    enum Error: Swift.Error {
        case badness
    }
    override func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        throw Error.badness
    }
}

// Wrapped here so that the test files don't need to use @testable import.
func sealedSenderMultiRecipientMessageForSingleRecipient(_ message: [UInt8]) throws -> [UInt8] {
    return try LibSignalClient.sealedSenderMultiRecipientMessageForSingleRecipient(message)
}

/// Always throws a ``XCTSkip`` error.
///
/// Add this to the top of a test case to make sure it compiles but never runs.
func throwSkipForCompileOnlyTest() throws {
    throw XCTSkip("compilation-only test")
}

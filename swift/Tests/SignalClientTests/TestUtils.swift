//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

@testable import SignalClient

class BadStore: InMemorySignalProtocolStore {
    enum Error: Swift.Error {
        case badness
    }
    override func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        throw Error.badness
    }
}

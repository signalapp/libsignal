//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient
import XCTest

class AccountEntropyTests: TestCaseBase {
    func testAccountEntropyPool() {
        let numTestIterations = 100
        var generatedEntropyPools = Set<String>()
        // generate() must return exactly 64 characters consisting only of a-z and 0-9.
        let validCharacters = Set<Character>("abcdefghijklmnopqrstuvwxyz0123456789")

        for _ in 0..<numTestIterations {
            let pool = AccountEntropyPool.generate()

            XCTAssertTrue(generatedEntropyPools.insert(pool).inserted, "Generated pool should be unique, got repeat: \(pool)")
            XCTAssertEqual(pool.count, 64, "Pool \(pool) is not the right length")
            for c in pool {
                XCTAssertTrue(validCharacters.contains(c), "Generated pool \(pool) contains invalid character \(c)")
            }
        }
    }

    func testKeyDerivations() {
        let pool = AccountEntropyPool.generate()

        let svrKey = try! AccountEntropyPool.deriveSvrKey(pool)
        XCTAssertEqual(32, svrKey.count)

        let backupKey = try! AccountEntropyPool.deriveBackupKey(pool)
        XCTAssertEqual(32, backupKey.serialize().count)

        let randomKey = BackupKey.generateRandom()
        XCTAssertNotEqual(backupKey.serialize(), randomKey.serialize())

        let uuid: uuid_t = (
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
        )
        let aci = Aci(fromUUID: UUID(uuid: uuid))
        let otherAci = Aci(fromUUID: UUID())

        let backupId = backupKey.deriveBackupId(aci: aci)
        XCTAssertEqual(16, backupId.count)
        XCTAssertNotEqual(backupId, randomKey.deriveBackupId(aci: aci))
        XCTAssertNotEqual(backupId, backupKey.deriveBackupId(aci: otherAci))

        let ecKey = backupKey.deriveEcKey(aci: aci)
        XCTAssertNotEqual(ecKey.serialize(), randomKey.deriveEcKey(aci: aci).serialize())
        XCTAssertNotEqual(ecKey.serialize(), backupKey.deriveEcKey(aci: otherAci).serialize())

        let localMetadataKey = backupKey.deriveLocalBackupMetadataKey()
        XCTAssertEqual(32, localMetadataKey.count)

        let mediaId = try! backupKey.deriveMediaId("example.jpg")
        XCTAssertEqual(15, mediaId.count)

        let mediaKey = try! backupKey.deriveMediaEncryptionKey(mediaId)
        XCTAssertEqual(32 + 32, mediaKey.count)

        XCTAssertThrowsError(try backupKey.deriveMediaEncryptionKey([0])) { error in
            switch error {
            case SignalError.invalidType(_): break
            default: XCTFail("unexpected error: \(error)")
            }
        }

        // This media ID wasn't for a thumbnail, but the API doesn't (can't) check that.
        let thumbnailKey = try! backupKey.deriveThumbnailTransitEncryptionKey(mediaId)
        XCTAssertEqual(32 + 32, thumbnailKey.count)
        XCTAssertNotEqual(mediaKey, thumbnailKey)
    }
}

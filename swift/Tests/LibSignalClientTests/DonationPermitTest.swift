//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient
import Testing

class DonationPermitTest {
    let TEST_ARRAY_32: Randomness = .init(
        (
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        )
    )

    let TEST_ARRAY_32_1: Randomness = .init(
        (
            0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73,
            0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83
        )
    )

    struct TestConfig {
        let secretParams: ServerSecretParams
        let publicParams: ServerPublicParams
        let now = Date(timeIntervalSince1970: 1_600_000_000)
        let expiration: Date
        let keyPair: DonationPermitDerivedKeyPair

        init(randomness: Randomness) throws {
            self.secretParams = try ServerSecretParams.generate(randomness: randomness)
            self.publicParams = try self.secretParams.getPublicParams()
            self.expiration = DonationPermitResponse.defaultExpiration(currentTime: self.now)
            self.keyPair = DonationPermitDerivedKeyPair.forExpiration(
                expiration: self.expiration,
                params: self.secretParams
            )
        }
        func issuePermits(_ count: Int, randomness: Randomness) throws -> [DonationPermit] {
            let context = try DonationPermitRequestContext.forCount(count: count)
            let response = context.request().issue(keyPair: self.keyPair, randomness: randomness)
            #expect(response.expiration == self.expiration)
            let permits = try context.receive(response: response, publicParams: self.publicParams, now: self.now)
            let dedupedIds: Set<Data> = Set(permits.map { $0.spendId })
            #expect(dedupedIds.count == count)
            return permits
        }
        func issueOnePermit(randomness: Randomness) throws -> DonationPermit {
            let out = try issuePermits(1, randomness: randomness)
            return out[0]
        }
    }
    @Test(arguments: [3, 10, 100])
    func defaultFlow(count: Int) throws {
        let config = try TestConfig(randomness: TEST_ARRAY_32)
        let permits = try config.issuePermits(count, randomness: TEST_ARRAY_32_1)
        for permit in permits {
            try permit.verify(keyPair: config.keyPair, now: config.now)
        }
    }
    @Test
    func wrongKeyFails() throws {
        let config = try TestConfig(randomness: TEST_ARRAY_32)
        let permit = try config.issueOnePermit(randomness: TEST_ARRAY_32_1)
        let otherSecret = try ServerSecretParams.generate()
        let wrongKey = DonationPermitDerivedKeyPair.forExpiration(expiration: config.expiration, params: otherSecret)
        #expect(throws: SignalError.self) {
            try permit.verify(keyPair: wrongKey, now: config.now)
        }
    }
    @Test
    func expiredPermitFails() throws {
        let config = try TestConfig(randomness: TEST_ARRAY_32)
        let permit = try config.issueOnePermit(randomness: TEST_ARRAY_32_1)
        let afterExpiry = config.expiration.advanced(by: TimeInterval(1))
        #expect(throws: SignalError.self) {
            try permit.verify(keyPair: config.keyPair, now: afterExpiry)
        }
    }
}

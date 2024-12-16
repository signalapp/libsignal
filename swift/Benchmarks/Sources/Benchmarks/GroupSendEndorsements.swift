//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Benchmark
import Foundation
import LibSignalClient

private let SECONDS_PER_DAY: UInt64 = 24 * 60 * 60

let groupSendEndorsementsSuite = BenchmarkSuite(name: "GroupSendEndorsements") { suite in
    let serverParams = try! ServerSecretParams.generate()
    let serverPublicParams = try! serverParams.getPublicParams()
    let groupParams = try! GroupSecretParams.generate()
    let now = UInt64(Date().timeIntervalSince1970)
    let startOfDay = now - now % SECONDS_PER_DAY
    let expiration = Date(timeIntervalSince1970: TimeInterval(startOfDay)).addingTimeInterval(TimeInterval(2 * SECONDS_PER_DAY))

    for groupSize in [10, 100, 1000] {
        let members = (0..<groupSize).map { _ in Aci(fromUUID: UUID()) }
        let cipher = ClientZkGroupCipher(groupSecretParams: groupParams)
        let encryptedMembers = members.map { try! cipher.encrypt($0) }

        let keyPair = GroupSendDerivedKeyPair.forExpiration(expiration, params: serverParams)
        let response = GroupSendEndorsementsResponse.issue(groupMembers: encryptedMembers, keyPair: keyPair)

        suite.benchmark("receiveWithServiceIds/\(groupSize)") {
            blackHole(try! response.receive(groupMembers: members, localUser: members[0], groupParams: groupParams, serverParams: serverPublicParams))
        }
        suite.benchmark("receiveWithCiphertexts/\(groupSize)") {
            blackHole(try! response.receive(groupMembers: encryptedMembers, localUser: encryptedMembers[0], serverParams: serverPublicParams))
        }

        let endorsements = try! response.receive(groupMembers: members, localUser: members[0], groupParams: groupParams, serverParams: serverPublicParams)

        suite.benchmark("toToken/\(groupSize)") {
            blackHole(endorsements.endorsements.map { $0.toToken(groupParams: groupParams) })
        }
    }
}

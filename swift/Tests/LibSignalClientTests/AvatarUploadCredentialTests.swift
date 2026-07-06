//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient
import Testing

private struct AvatarUploadCredentialTests {
    // Chosen randomly.
    let TEST_ACI = try! Aci.parseFrom(serviceIdString: "c0fc16e4-bae5-4343-9f0d-e7ecf4251343")

    let ZK_CRED_KEY_RANDOM = Randomness(
        fromHexString: "4242424242424242424242424242424242424242424242424242424242424242"
    )!

    let WRONG_ZK_CRED_KEY_RANDOM = Randomness(
        fromHexString: "9999999999999999999999999999999999999999999999999999999999999999"
    )!

    let SERVER_SECRET_RANDOM = Randomness(
        fromHexString: "6987b92bdea075d3f8b42b39d780a5be0bc264874a18e11cac694e4fe28f6cca"
    )!

    let CREATE_RANDOM = Randomness(
        fromHexString: "657e7a2ac9dd981b789c9b2fbcdfbbe46cb6230c7a2c67c1be3472cb006463e2"
    )!

    let ISSUE_RANDOM = Randomness(
        fromHexString: "8e3f24cb0a7e7614c7b4ab04ba8a145f108c53c4b10a096aa4503ae1e0c9f661"
    )!

    let PRESENT_RANDOM = Randomness(
        fromHexString: "475149b2bdcb6f9bd3a8e3a5d4c6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"
    )!

    let ROTATION_ID: UInt64 = 7

    @Test
    func testAvatarUploadCredentialIntegration() {
        // SERVER: generate keys.
        let serverSecretParams = GenericServerSecretParams.generate(randomness: SERVER_SECRET_RANDOM)
        let serverPublicParams = serverSecretParams.getPublicParams()

        // CLIENT: generate its long-term ZK credential key pair and (out of band) register the public
        // half with the server.
        let zkCredentialKeyPair = ZkCredentialKeyPair.generate(randomness: ZK_CRED_KEY_RANDOM)
        let zkCredentialKeyPublic = zkCredentialKeyPair.publicKey

        // CLIENT: build a request.
        let context = AvatarUploadCredentialRequestContext.create(
            aci: TEST_ACI,
            zkCredentialKey: zkCredentialKeyPair,
            rotationId: ROTATION_ID,
            randomness: CREATE_RANDOM
        )
        let request = context.getRequest()

        // Round-tripping the request through serialize() must preserve it.
        #expect(request.serialize() == (try! AvatarUploadCredentialRequest(contents: request.serialize()).serialize()))

        // SERVER: authenticate the ACI, look up its ZK credential key, and issue.
        let now = Date()
        let nowInSeconds = UInt64(now.timeIntervalSince1970)
        let startOfDayInSeconds = nowInSeconds - (nowInSeconds % SECONDS_PER_DAY)
        let startOfDay = Date(timeIntervalSince1970: TimeInterval(startOfDayInSeconds))
        let response = try! request.issueCredential(
            aci: TEST_ACI,
            zkCredentialKey: zkCredentialKeyPublic,
            rotationId: ROTATION_ID,
            redemptionTime: startOfDay,
            serverParams: serverSecretParams,
            randomness: ISSUE_RANDOM
        )

        // CLIENT: verify and unblind the credential. The client passes its current wall-clock time;
        // libsignal checks that the credential's redemption_time (chosen by the server, carried in
        // `response`) is day-aligned and inside the redemption window relative to `now`.
        let credential = try! context.receive(response, now: now, serverParams: serverPublicParams)

        // The client can read back the redemption time the issuing server chose.
        #expect(startOfDay == credential.redemptionTime)

        let credentialDefaultTime = try! context.receive(response, serverParams: serverPublicParams)
        #expect(credential.serialize() == credentialDefaultTime.serialize())

        // CLIENT: present the credential.
        let presentation = credential.present(serverParams: serverPublicParams, randomness: PRESENT_RANDOM)

        // The revealed commitment Cm must match between the credential and its presentation.
        #expect(credential.commitment == presentation.commitment)
        #expect(credential.redemptionTime == presentation.redemptionTime)

        // SERVER: verify the presentation across the redemption window.
        try! presentation.verify(now: startOfDay, serverParams: serverSecretParams)
        try! presentation.verify(now: startOfDay + TimeInterval(SECONDS_PER_DAY), serverParams: serverSecretParams)

        #expect("Credential should be expired more than 2 days after redemption time") {
            try presentation.verify(
                now: startOfDay + 2 * TimeInterval(SECONDS_PER_DAY + 1),
                serverParams: serverSecretParams
            )
        } throws: {
            if case SignalError.verificationFailed(_:) = $0 { true } else { false }
        }

        #expect("Credential should be invalid before its redemption time") {
            try presentation.verify(
                now: startOfDay - TimeInterval(SECONDS_PER_DAY + 1),
                serverParams: serverSecretParams
            )
        } throws: {
            if case SignalError.verificationFailed(_:) = $0 { true } else { false }
        }
    }

    @Test
    func testIssuanceRejectsWrongAci() {
        let serverSecretParams = GenericServerSecretParams.generate(randomness: SERVER_SECRET_RANDOM)

        let zkCredentialKeyPair = ZkCredentialKeyPair.generate(randomness: ZK_CRED_KEY_RANDOM)
        let zkCredentialKeyPublic = zkCredentialKeyPair.publicKey

        let context = AvatarUploadCredentialRequestContext.create(
            aci: TEST_ACI,
            zkCredentialKey: zkCredentialKeyPair,
            rotationId: ROTATION_ID,
            randomness: CREATE_RANDOM
        )
        let request = context.getRequest()

        let wrongAci = try! Aci.parseFrom(serviceIdString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

        let now = Date()
        let nowInSeconds = UInt64(now.timeIntervalSince1970)
        let startOfDayInSeconds = nowInSeconds - (nowInSeconds % SECONDS_PER_DAY)
        let startOfDay = Date(timeIntervalSince1970: TimeInterval(startOfDayInSeconds))

        #expect("Issuance should fail when the server checks against a different ACI") {
            try request.issueCredential(
                aci: wrongAci,
                zkCredentialKey: zkCredentialKeyPublic,
                rotationId: ROTATION_ID,
                redemptionTime: startOfDay,
                serverParams: serverSecretParams,
                randomness: ISSUE_RANDOM
            )
        } throws: {
            if case SignalError.verificationFailed(_:) = $0 { true } else { false }
        }
    }

    @Test
    func testIssuanceRejectsWrongZkCredentialKey() {
        let serverSecretParams = GenericServerSecretParams.generate(randomness: SERVER_SECRET_RANDOM)

        let zkCredentialKeyPair = ZkCredentialKeyPair.generate(randomness: ZK_CRED_KEY_RANDOM)

        let context = AvatarUploadCredentialRequestContext.create(
            aci: TEST_ACI,
            zkCredentialKey: zkCredentialKeyPair,
            rotationId: ROTATION_ID,
            randomness: CREATE_RANDOM
        )
        let request = context.getRequest()

        // Server has a different ZK credential public key on file for this account.
        let wrongZkCredentialKeyPublic = ZkCredentialKeyPair.generate(randomness: WRONG_ZK_CRED_KEY_RANDOM).publicKey

        let now = Date()
        let nowInSeconds = UInt64(now.timeIntervalSince1970)
        let startOfDayInSeconds = nowInSeconds - (nowInSeconds % SECONDS_PER_DAY)
        let startOfDay = Date(timeIntervalSince1970: TimeInterval(startOfDayInSeconds))

        #expect("Issuance should fail when the server uses a different ZK credential public key") {
            try request.issueCredential(
                aci: TEST_ACI,
                zkCredentialKey: wrongZkCredentialKeyPublic,
                rotationId: ROTATION_ID,
                redemptionTime: startOfDay,
                serverParams: serverSecretParams,
                randomness: ISSUE_RANDOM
            )
        } throws: {
            if case SignalError.verificationFailed(_:) = $0 { true } else { false }
        }
    }

    @Test
    func testIssuanceRejectsWrongRotationId() {
        let serverSecretParams = GenericServerSecretParams.generate(randomness: SERVER_SECRET_RANDOM)

        let zkCredentialKeyPair = ZkCredentialKeyPair.generate(randomness: ZK_CRED_KEY_RANDOM)
        let zkCredentialKeyPublic = zkCredentialKeyPair.publicKey

        // Client commits to one rotation ID...
        let context = AvatarUploadCredentialRequestContext.create(
            aci: TEST_ACI,
            zkCredentialKey: zkCredentialKeyPair,
            rotationId: ROTATION_ID,
            randomness: CREATE_RANDOM
        )
        let request = context.getRequest()

        let now = Date()
        let nowInSeconds = UInt64(now.timeIntervalSince1970)
        let startOfDayInSeconds = nowInSeconds - (nowInSeconds % SECONDS_PER_DAY)
        let startOfDay = Date(timeIntervalSince1970: TimeInterval(startOfDayInSeconds))

        #expect("Issuance should fail when the server uses a different rotation ID") {
            try request.issueCredential(
                aci: TEST_ACI,
                zkCredentialKey: zkCredentialKeyPublic,
                rotationId: ROTATION_ID + 1,
                redemptionTime: startOfDay,
                serverParams: serverSecretParams,
                randomness: ISSUE_RANDOM
            )
        } throws: {
            if case SignalError.verificationFailed(_:) = $0 { true } else { false }
        }
    }

    @Test
    func testPublicKeyDerivationIsDeterministic() {
        let a = ZkCredentialKeyPair.generate(randomness: ZK_CRED_KEY_RANDOM)
        let b = ZkCredentialKeyPair.generate(randomness: ZK_CRED_KEY_RANDOM)
        #expect(a.serialize() == b.serialize())
        #expect(a.publicKey.serialize() == b.publicKey.serialize())
    }
}

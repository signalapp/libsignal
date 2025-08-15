//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi
import Testing

@testable import LibSignalClient

// These tests depend on test-only functions that aren't available on device builds to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class RegistrationServiceConversionTests {
    private struct ErrorTest {
        public let operationName: String
        public let convertFn: (UnsafePointer<CChar>) -> OpaquePointer?
        public let cases: [(String, (Error) -> Bool)]
        public init(
            _ operationName: String,
            _ convertFn: @escaping (UnsafePointer<CChar>) -> OpaquePointer?,
            _ cases: [(String, (Error) -> Bool)]
        ) {
            self.operationName = operationName
            self.convertFn = convertFn
            self.cases = cases
        }
    }

    @Test
    func registrationSessionStateConversion() throws {
        let sessionState: RegistrationSessionState = try invokeFnReturningNativeHandle {
            signal_testing_registration_session_info_convert($0)
        }
        #expect(sessionState.allowedToRequestCode == true)
        #expect(sessionState.verified == true)
        #expect(sessionState.nextCall == TimeInterval(123))
        #expect(sessionState.nextSms == TimeInterval(456))
        #expect(sessionState.nextVerificationAttempt == TimeInterval(789))
        #expect(sessionState.requestedInformation == [.pushChallenge])
    }

    @Test
    func registerAccountResponseConversion() throws {
        let response: RegisterAccountResponse = try invokeFnReturningNativeHandle {
            signal_testing_register_account_response_create_test_value($0)
        }
        #expect(response.number == "+18005550123")
        #expect(try Aci.parseFrom(serviceIdString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") == response.aci)
        #expect(try Pni.parseFrom(serviceIdString: "PNI:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb") == response.pni)
        #expect(response.usernameHash == Data("username-hash".utf8))
        #expect(response.usernameLinkHandle == UUID(uuidString: "55555555-5555-5555-5555-555555555555"))
        #expect(response.storageCapable == true)
        #expect(
            response.entitlements.0 == [
                BadgeEntitlement(id: "first", visible: true, expiration: 123_456),
                BadgeEntitlement(id: "second", visible: false, expiration: 555),
            ]
        )
        #expect(response.entitlements.1 == BackupEntitlement(expiration: 888_888, level: 123))
        #expect(response.reregistration == true)
    }

    // swift-format-ignore
    // The long lines are one-per-test-case; it's clearer to see the form like this.
    // They'd get shorter if Swift added a `matches!` equivalent.
    @Test
    func errorConversion() {
        let retryLaterCase = ("RetryAfter42Seconds", { (e: Error) in if case SignalError.rateLimitedError(retryAfter: 42, message: "Rate limited; try again after 42s") = e { true } else { false }})
        let unknownCase = ("Unknown", { (e: Error) in if case RegistrationError.unknown("some message") = e { true } else { false }})
        let timeoutCase = ("Timeout", { (e: Error) in if case SignalError.requestTimeoutError("the request timed out") = e { true } else { false }})
        let requestNotValidCase = ("RequestWasNotValid", { (e: Error) in if case RegistrationError.unknown("the request did not pass server validation") = e { true } else { false }})
        let serverErrorCase = ("ServerSideError", { (e: Error) in if case RegistrationError.unknown("server-side error, retryable with backoff") = e { true } else { false }})
        let pushChallengeCase = ("PushChallenge", { (e: Error) in if case SignalError.rateLimitChallengeError(token: "token", options: [.pushChallenge], message: "retry after completing a rate limit challenge [PushChallenge]") = e { true } else { false }})

        let cases = [
            ErrorTest("CreateSession", signal_testing_registration_service_create_session_error_convert, [
                ("InvalidSessionId", { if case RegistrationError.invalidSessionId("invalid session ID value") = $0 { true } else { false }}),
                retryLaterCase,
                unknownCase,
                timeoutCase,
                requestNotValidCase,
                serverErrorCase,
                pushChallengeCase,
            ]),
            ErrorTest("ResumeSession", signal_testing_registration_service_resume_session_error_convert, [
                ("InvalidSessionId", { if case RegistrationError.invalidSessionId("invalid session ID value") = $0 { true } else { false }}),
                ("SessionNotFound", { if case RegistrationError.sessionNotFound("session not found") = $0 { true } else { false }}),
                unknownCase,
                timeoutCase,
                requestNotValidCase,
                serverErrorCase,
                pushChallengeCase,
            ]),
            ErrorTest(
                "UpdateSession",
                signal_testing_registration_service_update_session_error_convert,
                [
                    ("Rejected", { if case RegistrationError.sessionUpdateRejected("the information provided was rejected") = $0 { true } else { false }}),
                    retryLaterCase,
                    unknownCase,
                    timeoutCase,
                    requestNotValidCase,
                    serverErrorCase,
                ]
            ),
            ErrorTest(
                "RequestVerificationCode",
                signal_testing_registration_service_request_verification_code_error_convert,
                [
                    ("InvalidSessionId", { if case RegistrationError.invalidSessionId("invalid session ID value") = $0 { true } else { false }}),
                    ("SessionNotFound", { if case RegistrationError.sessionNotFound("session not found") = $0 { true } else { false }}),
                    ("NotReadyForVerification", { if case RegistrationError.notReadyForVerification("the session is already verified or not ready for a code request") = $0 { true } else { false }}),
                    ("SendFailed", { if case RegistrationError.sendVerificationFailed("the request to send a verification code with the requested transport could not be fulfilled") = $0 { true } else { false }}),
                    ("CodeNotDeliverable", { if case RegistrationError.codeNotDeliverable(message: "no reason", permanentFailure: true) = $0 { true } else { false }}),
                    retryLaterCase,
                    unknownCase,
                    timeoutCase,
                    requestNotValidCase,
                    serverErrorCase,
                ]
            ),
            ErrorTest(
                "SubmitVerification",
                signal_testing_registration_service_submit_verification_error_convert,
                [
                    ("InvalidSessionId", { if case RegistrationError.invalidSessionId("invalid session ID value") = $0 { true } else { false }}),
                    ("SessionNotFound", { if case RegistrationError.sessionNotFound("session not found") = $0 { true } else { false }}),
                    ("NotReadyForVerification", { if case RegistrationError.notReadyForVerification("the session is already verified or no code was requested") = $0 { true } else { false }}),
                    retryLaterCase,
                    unknownCase,
                    timeoutCase,
                    requestNotValidCase,
                    serverErrorCase,
                ]
            ),
            ErrorTest(
                "CheckSvr2Credentials",
                signal_testing_registration_service_check_svr2_credentials_error_convert,
                [
                    ("CredentialsCouldNotBeParsed", { if case RegistrationError.credentialsCouldNotBeParsed("provided list of SVR2 credentials could not be parsed.") = $0 { true } else { false }}),
                    unknownCase,
                    timeoutCase,
                    requestNotValidCase,
                    serverErrorCase,
                ]
            ),
            ErrorTest(
                "RegisterAccount",
                signal_testing_registration_service_register_account_error_convert,
                [
                    ("DeviceTransferIsPossibleButNotSkipped", { if case RegistrationError.deviceTransferPossible("a device transfer is possible and was not explicitly skipped.") = $0 { true } else { false }}),
                    ("RegistrationRecoveryVerificationFailed", { if case RegistrationError.recoveryVerificationFailed("registration recovery password verification failed") = $0 { true } else { false }}),
                    ("RegistrationLockFor50Seconds", { if case RegistrationError.registrationLock(timeRemaining: 50, svr2Username: "user", svr2Password: "pass") = $0 { true } else { false }}),
                    retryLaterCase,
                    unknownCase,
                    timeoutCase,
                    serverErrorCase,
                ]
            ),
        ]

        for item in cases {
            for (desc, checkErrorExpected) in item.cases {
                do {
                    try desc.withCString { errorCase in
                        try checkError(item.convertFn(errorCase))
                    }
                    Issue.record("exception expected")
                } catch let e {
                    #expect(checkErrorExpected(e))
                }
            }
        }
    }

    @Test
    func checkSvr2CredentialsConvert() throws {
        let expectedEntries = [
            "username:pass-match": Svr2CredentialsResult.match,
            "username:pass-no-match": Svr2CredentialsResult.noMatch,
            "username:pass-invalid": Svr2CredentialsResult.invalid,
        ]

        #expect(
            try invokeFnReturningCheckSvr2CredentialsResponse(
                fn: signal_testing_registration_service_check_svr2_credentials_response_convert
            ) == expectedEntries
        )
    }

    @Test
    func convertSignedPreKey() throws {
        let key = PrivateKey.generate().publicKey
        let signedPublicPreKey = SignedPublicPreKey(keyId: 42, publicKey: key, signature: Data("signature".utf8))

        try key.withNativeHandle { key in
            try signedPublicPreKey.withNativeStruct { signedPublicPreKey in
                try checkError(
                    signal_testing_signed_public_pre_key_check_bridges_correctly(key.const(), signedPublicPreKey)
                )
            }
        }
    }
}

class RegistrationServiceFakeChatTests {
    @Test
    func fakeRemoteCreateSession() async throws {
        let tokio = TokioAsyncContext()
        let server = FakeChatServer(asyncContext: tokio)
        async let startCreateSessionRequest =
            RegistrationService.fakeCreateSession(
                fakeChatServer: server,
                e164: "+18005550123",
                pushToken: "myPushToken"
            )

        let fakeRemote = try await server.getNextRemote()
        let (firstRequest, firstRequestId) = try await fakeRemote.getNextIncomingRequest()

        #expect(firstRequest.method == "POST")
        #expect(firstRequest.pathAndQuery == "/v1/verification/session")

        try fakeRemote.sendResponse(
            requestId: firstRequestId,
            ChatResponse(
                status: 200,
                message: "OK",
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "allowedToRequestCode": true,
                        "verified": false,
                        "requestedInformation": ["pushChallenge", "captcha"],
                        "id": "fake-session-A"
                    }
                    """.utf8
                )
            )
        )

        let session = try await startCreateSessionRequest
        #expect(session.sessionId == "fake-session-A")

        let sessionState = session.sessionState
        #expect(sessionState.verified == false)
        #expect(
            sessionState.requestedInformation == [
                .pushChallenge,
                .captcha,
            ]
        )

        async let requestVerification: () = session.requestVerificationCode(
            transport: .voice,
            client: "libsignal test",
            languages: ["fr-CA"]
        )

        let (secondRequest, secondRequestId) = try await fakeRemote.getNextIncomingRequest()

        #expect(secondRequest.method == "POST")
        #expect(secondRequest.pathAndQuery == "/v1/verification/session/fake-session-A/code")
        #expect(
            secondRequest.body
                == Data(
                    """
                    {"transport":"voice","client":"libsignal test"}
                    """.utf8
                )
        )
        #expect(
            secondRequest.headers == ["content-type": "application/json", "accept-language": "fr-CA"]
        )

        try fakeRemote.sendResponse(
            requestId: secondRequestId,
            ChatResponse(
                status: 200,
                message: "OK",
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "allowedToRequestCode": true,
                        "verified": false,
                        "requestedInformation": ["captcha"],
                        "id": "fake-session-A"
                    }
                    """
                    .utf8
                )
            )
        )

        let () = try await requestVerification
        #expect(session.sessionState.requestedInformation == [.captcha])
    }

    @Test
    func fakeRemoteRegisterAccount() async throws {
        let tokio = TokioAsyncContext()
        let server = FakeChatServer(asyncContext: tokio)
        async let startCreateSessionRequest =
            RegistrationService.fakeCreateSession(
                fakeChatServer: server,
                e164: "+18005550123",
                pushToken: "myPushToken"
            )

        let fakeRemote = try await server.getNextRemote()
        let (firstRequest, firstRequestId) = try await fakeRemote.getNextIncomingRequest()
        // The request contents are checked by another test.
        _ = firstRequest

        // Send a response to allow the request to complete.
        try fakeRemote.sendResponse(
            requestId: firstRequestId,
            ChatResponse(
                status: 200,
                message: "OK",
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "allowedToRequestCode": true,
                        "verified": false,
                        "requestedInformation": ["pushChallenge", "captcha"],
                        "id": "fake-session-A"
                    }
                    """
                    .utf8
                )
            )
        )

        let session = try await startCreateSessionRequest
        #expect(session.sessionId == "fake-session-A")

        let unidentifiedAccessKey = Data(repeating: 0x55, count: 16)
        let aciKeys = RegisterAccountKeys.createForTest()
        let pniKeys = RegisterAccountKeys.createForTest()
        async let registerAccount =
            session.registerAccount(
                accountPassword: "account password",
                skipDeviceTransfer: true,
                accountAttributes: RegisterAccountAttributes(
                    recoveryPassword: Data("recovery password".utf8),
                    aciRegistrationId: 1,
                    pniRegistrationId: 2,
                    registrationLock: "registration lock",
                    unidentifiedAccessKey: unidentifiedAccessKey,
                    unrestrictedUnidentifiedAccess:
                        true,
                    capabilities: ["capable"],
                    discoverableByPhoneNumber: true
                ),
                apnPushToken: "push token",
                aciPublicKey: aciKeys.publicKey,
                pniPublicKey: pniKeys.publicKey,
                aciSignedPreKey: aciKeys.signedPreKey,
                pniSignedPreKey: pniKeys.signedPreKey,
                aciPqLastResortPreKey: aciKeys.pqLastResortPreKey,
                pniPqLastResortPreKey: pniKeys.pqLastResortPreKey
            )

        let (secondRequest, secondRequestId) = try await fakeRemote.getNextIncomingRequest()

        #expect(secondRequest.method == "POST")
        #expect(secondRequest.pathAndQuery == "/v1/registration")

        #expect(
            [
                "content-type": "application/json",
                "authorization": "Basic " + Data("+18005550123:account password".utf8).base64EncodedString(),
            ] == secondRequest.headers
        )

        let secondRequestBodyJson = try JSONSerialization.jsonObject(with: secondRequest.body)
        guard let secondRequestJson: [String: Any] = secondRequestBodyJson as? [String: Any] else {
            fatalError("body was \(secondRequestBodyJson)")
        }

        #expect(secondRequestJson["sessionId"] as? String == "fake-session-A")
        #expect(secondRequestJson["skipDeviceTransfer"] as? Bool == true)
        do {
            guard let accountAttributes = secondRequestJson["accountAttributes"] as? [String: Any] else {
                fatalError("accountAttributes was \(String(describing: secondRequestJson["accountAttributes"]))")
            }
            #expect(
                accountAttributes["recoveryPassword"] as? String == "cmVjb3ZlcnkgcGFzc3dvcmQ="
            )
            #expect(accountAttributes["registrationId"] as? Double == 1)
            #expect(accountAttributes["pniRegistrationId"] as? Double == 2)
            #expect(accountAttributes["registrationLock"] as? String == "registration lock")
            #expect(accountAttributes["unidentifiedAccessKey"] as? Array == Array(repeating: 0x55, count: 16))
            #expect(accountAttributes["unrestrictedUnidentifiedAccess"] as? Bool == true)
            #expect(accountAttributes["capabilities"] as? [String: Bool] == ["capable": true])
            #expect(accountAttributes["discoverableByPhoneNumber"] as? Bool == true)
            #expect(accountAttributes["fetchesMessages"] as? Bool == false)
        }

        #expect(
            Data(aciKeys.publicKey.serialize()).base64EncodedString() == secondRequestJson["aciIdentityKey"] as? String
        )
        #expect(
            Data(pniKeys.publicKey.serialize()).base64EncodedString() == secondRequestJson["pniIdentityKey"] as? String
        )

        // We don't need to check all the keys, just one of each kind is enough.
        do {
            guard let aciSignedPreKey = secondRequestJson["aciSignedPreKey"] as? [String: Any] else {
                fatalError("aciSignedPreKey was \(String(describing: secondRequestJson["aciSignedPreKey"]))")
            }
            #expect(aciSignedPreKey["signature"] as? String == Data("EC signature".utf8).base64EncodedString())
            #expect(aciSignedPreKey["keyId"] as? Double == 1)
            #expect(
                aciSignedPreKey["publicKey"] as? String
                    == Data(aciKeys.signedPreKey.publicKey.serialize()).base64EncodedString()
            )

            guard let aciPqLastResortPreKey = secondRequestJson["aciPqLastResortPreKey"] as? [String: Any] else {
                fatalError("aciSignedPreKey was \(String(describing: secondRequestJson["aciPqLastResortPreKey"]))")
            }
            #expect(aciPqLastResortPreKey["signature"] as? String == Data("KEM signature".utf8).base64EncodedString())
            #expect(aciPqLastResortPreKey["keyId"] as? Double == 2)
            #expect(
                aciPqLastResortPreKey["publicKey"] as? String
                    == Data(aciKeys.pqLastResortPreKey.publicKey.serialize()).base64EncodedString()
            )
        }

        try fakeRemote.sendResponse(
            requestId: secondRequestId,
            ChatResponse(
                status: 200,
                message: "OK",
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "uuid": "aabbaabb-5555-6666-8888-111111111111",
                        "pni": "ddeeddee-5555-6666-8888-111111111111",
                        "number": "+18005550123",
                        "storageCapable": true,
                        "entitlements": {
                            "badges": [{
                                "id": "one",
                                "visible": true,
                                "expirationSeconds": 13
                            },{
                                "id": "two",
                                "visible": false,
                                "expirationSeconds": 66666
                            }],
                            "backup": {
                                "backupLevel": 1569,
                                "expirationSeconds": 987654321
                            }
                        }
                    }
                    """
                    .utf8
                )
            )
        )

        let response = try await registerAccount
        // We only perform a cursory check here because there is a already a dedicated test for bridging
        // the response.
        #expect(response.aci.serviceIdString == "aabbaabb-5555-6666-8888-111111111111")
        #expect(response.pni.serviceIdString == "PNI:ddeeddee-5555-6666-8888-111111111111")
        #expect(response.number == "+18005550123")
    }

    private struct RegisterAccountKeys: Sendable {
        public let publicKey: PublicKey
        public let signedPreKey: SignedPublicPreKey<PublicKey>
        public let pqLastResortPreKey: SignedPublicPreKey<KEMPublicKey>

        public static func createForTest() -> Self {
            return RegisterAccountKeys(
                publicKey: PrivateKey.generate().publicKey,
                signedPreKey: SignedPublicPreKey(
                    keyId: 1,
                    publicKey: PrivateKey.generate().publicKey,
                    signature: Data("EC signature".utf8)
                ),
                pqLastResortPreKey: SignedPublicPreKey(
                    keyId: 2,
                    publicKey: KEMKeyPair.generate().publicKey,
                    signature: Data(
                        "KEM signature".utf8
                    )
                )
            )
        }
    }
}

extension RegistrationService {
    static func fakeCreateSession(
        fakeChatServer: FakeChatServer,
        e164: String,
        pushToken: String?,
        mcc: String? = nil,
        mnc: String? = nil
    ) async throws -> RegistrationService {
        let registrationService: SignalMutPointerRegistrationService = try await fakeChatServer.asyncContext
            .invokeAsyncFunction { promise, asyncContext in
                SignalFfiRegistrationCreateSessionRequest.withNativeStruct(
                    e164: e164,
                    pushToken: pushToken,
                    mcc: mcc,
                    mnc: mnc
                ) { request in
                    fakeChatServer.withNativeHandle { fakeChatServer in
                        signal_testing_fake_registration_session_create_session(
                            promise,
                            asyncContext.const(),
                            request,
                            fakeChatServer.const()
                        )
                    }
                }
            }
        return RegistrationService(owned: NonNull(registrationService)!, asyncContext: fakeChatServer.asyncContext)
    }
}

#endif

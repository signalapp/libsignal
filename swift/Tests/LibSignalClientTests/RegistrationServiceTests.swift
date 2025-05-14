//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
@testable import LibSignalClient
import SignalFfi
import XCTest

// These tests depend on test-only functions that aren't available on device builds to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class RegistrationServiceConversionTests: XCTestCase {
    private struct ErrorTest {
        public let operationName: String
        public let convertFn: (_: UnsafePointer<CChar>) -> OpaquePointer?
        public let cases: [(String, (Error) -> Bool)]
        public init(
            _ operationName: String,
            _ convertFn: @escaping (_: UnsafePointer<CChar>) -> OpaquePointer?,
            _ cases: [(String, (Error) -> Bool)]
        ) {
            self.operationName = operationName
            self.convertFn = convertFn
            self.cases = cases
        }
    }

    func testRegistrationSessionStateConversion() throws {
        let sessionState: RegistrationSessionState = try invokeFnReturningNativeHandle {
            signal_testing_registration_session_info_convert($0)
        }
        XCTAssertEqual(sessionState.allowedToRequestCode, true)
        XCTAssertEqual(sessionState.verified, true)
        XCTAssertEqual(sessionState.nextCall, TimeInterval(123))
        XCTAssertEqual(sessionState.nextSms, TimeInterval(456))
        XCTAssertEqual(sessionState.nextVerificationAttempt, TimeInterval(789))
        XCTAssertEqual(sessionState.requestedInformation, [.pushChallenge])
    }

    func testRegisterAccountResponseConversion() throws {
        let response: RegisterAccountResponse = try invokeFnReturningNativeHandle {
            signal_testing_register_account_response_create_test_value($0)
        }
        XCTAssertEqual(response.number, "+18005550123")
        XCTAssertEqual(response.aci, try Aci.parseFrom(serviceIdString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
        XCTAssertEqual(response.pni, try Pni.parseFrom(serviceIdString: "PNI:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"))
        XCTAssertEqual(response.usernameHash, Array("username-hash".utf8))
        XCTAssertEqual(response.usernameLinkHandle, UUID(uuidString: "55555555-5555-5555-5555-555555555555"))
        XCTAssertEqual(response.storageCapable, true)
        XCTAssertEqual(response.entitlements.0, [
            BadgeEntitlement(id: "first", visible: true, expiration: 123_456),
            BadgeEntitlement(id: "second", visible: false, expiration: 555),
        ])
        XCTAssertEqual(response.entitlements.1, BackupEntitlement(expiration: 888_888, level: 123))
        XCTAssertEqual(response.reregistration, true)
    }

    func testErrorConversion() {
        let retryLaterCase = ("RetryAfter42Seconds", { (e: Error) in if case SignalError.rateLimitedError(retryAfter: 42, message: "retry after 42s") = e { true } else { false }})
        let unknownCase = ("Unknown", { (e: Error) in if case RegistrationError.unknown("unknown error: some message") = e { true } else { false }})
        let timeoutCase = ("Timeout", { (e: Error) in if case SignalError.requestTimeoutError("the request timed out") = e { true } else { false }})
        let requestNotValidCase = ("RequestWasNotValid", { (e: Error) in if case RegistrationError.requestNotValid("the request did not pass server validation") = e { true } else { false }})

        let cases = [
            ErrorTest("CreateSession", signal_testing_registration_service_create_session_error_convert, [
                ("InvalidSessionId", { if case RegistrationError.invalidSessionId("invalid session ID value") = $0 { true } else { false }}),
                retryLaterCase,
                unknownCase,
                timeoutCase,
                requestNotValidCase,
            ]),
            ErrorTest("ResumeSession", signal_testing_registration_service_resume_session_error_convert, [
                ("InvalidSessionId", { if case RegistrationError.invalidSessionId("invalid session ID value") = $0 { true } else { false }}),
                ("SessionNotFound", { if case RegistrationError.sessionNotFound("session not found") = $0 { true } else { false }}),
                unknownCase,
                timeoutCase,
                requestNotValidCase,
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
                ]
            ),
        ]

        for item in cases {
            for (desc, checkErrorExpected) in item.cases {
                do {
                    try desc.withCString { errorCase in
                        try checkError(item.convertFn(errorCase))
                    }
                    XCTFail("exception expected")
                } catch let e {
                    XCTAssert(checkErrorExpected(e), String(describing: e))
                }
            }
        }
    }

    func testCheckSvr2CredentialsConvert() {
        let expectedEntries = [
            "username:pass-match": Svr2CredentialsResult.match,
            "username:pass-no-match": Svr2CredentialsResult.noMatch,
            "username:pass-invalid": Svr2CredentialsResult.invalid,
        ]

        XCTAssertEqual(
            try invokeFnReturningCheckSvr2CredentialsResponse(fn: signal_testing_registration_service_check_svr2_credentials_response_convert),
            expectedEntries
        )
    }
}

class RegistrationServiceFakeChatTests: XCTestCase {
    public func testFakeRemoteCreateSession() async throws {
        let tokio = TokioAsyncContext()
        let server = FakeChatServer(asyncContext: tokio)
        async let startCreateSessionRequest =
            RegistrationService.fakeCreateSession(
                fakeChatServer: server,
                e164: "+18005550123", pushToken: "myPushToken"
            )

        let fakeRemote = try await server.getNextRemote()
        let (firstRequest, firstRequestId) = try await fakeRemote.getNextIncomingRequest()

        XCTAssertEqual(firstRequest.method, "POST")
        XCTAssertEqual(firstRequest.pathAndQuery, "/v1/verification/session")

        try fakeRemote.sendResponse(
            requestId: firstRequestId,
            ChatResponse(
                status: 200,
                message: "OK",
                headers: ["content-type": "application/json"],
                body: Data("""
                    {
                        "allowedToRequestCode": true,
                        "verified": false,
                        "requestedInformation": ["pushChallenge", "captcha"],
                        "id": "fake-session-A"
                    }
                    """.utf8)
            )
        )

        let session = try await startCreateSessionRequest
        XCTAssertEqual(session.sessionId, "fake-session-A")

        let sessionState = session.sessionState
        XCTAssertEqual(sessionState.verified, false)
        XCTAssertEqual(
            sessionState.requestedInformation,
            [
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

        XCTAssertEqual(secondRequest.method, "POST")
        XCTAssertEqual(secondRequest.pathAndQuery, "/v1/verification/session/fake-session-A/code")
        XCTAssertEqual(
            secondRequest.body,
            Data("""
                {"transport":"voice","client":"libsignal test"}
                """.utf8)
        )
        XCTAssertEqual(
            secondRequest.headers,
            ["content-type": "application/json", "accept-language": "fr-CA"]
        )

        try fakeRemote.sendResponse(
            requestId: secondRequestId,
            ChatResponse(
                status: 200,
                message: "OK",
                headers: ["content-type": "application/json"],
                body: Data("""
                    {
                        "allowedToRequestCode": true,
                        "verified": false,
                        "requestedInformation": ["captcha"],
                        "id": "fake-session-A"
                    }
                    """
                    .utf8)
            )
        )

        let () = try await requestVerification
        XCTAssertEqual(session.sessionState.requestedInformation, [.captcha])
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
        let registrationService: SignalMutPointerRegistrationService = try await fakeChatServer.asyncContext.invokeAsyncFunction { promise, asyncContext in
            SignalFfiRegistrationCreateSessionRequest.withNativeStruct(e164: e164, pushToken: pushToken, mcc: mcc, mnc: mnc) { request in
                fakeChatServer.withNativeHandle { fakeChatServer in
                    signal_testing_fake_registration_session_create_session(promise, asyncContext.const(), request, fakeChatServer.const())
                }
            }
        }
        return RegistrationService(owned: NonNull(registrationService)!, asyncContext: fakeChatServer.asyncContext)
    }
}

#endif

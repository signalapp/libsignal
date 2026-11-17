//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthProfilesServiceTests: AuthChatServiceTestBase<any AuthProfilesService> {
    override class var selector: SelectorCheck { .profiles }

    func testGetAvatarUploadFormLegacy() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetAvatarUploadFormLegacyTests(),
            invoke: { api, args in
                try await api.getAvatarUploadFormLegacy(
                    aci: args.aci,
                    profileKey: args.profileKey,
                )
            },
            check: { expected, actual in
                XCTAssertEqual(expected, try actual.get())
            }
        )
    }
}
class AuthProfilesServiceImplTests: AuthChatServiceTestBase<AuthenticatedChatConnection> {
    override class var selector: SelectorCheck { .allAuthenticatedConnection }

    func testGetAvatarCredential() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetAvatarCredentialTests(),
            invoke: { api, args in
                try await api.getAvatarCredentialImpl(
                    aci: args.aci,
                    keyPair: args.keyPair,
                    rotationId: args.rotationId,
                    serverPublicParams: args.serverPublicParams,
                    currentTimeSeconds: Date(timeIntervalSince1970: TimeInterval(args.currentTimeSeconds)),
                    rng: 0,
                )
            },
            check: { expected, actual in
                if let cred = expected {
                    XCTAssertEqual((try actual.get()).serialize(), cred.serialize())
                } else {
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.accountMissingZkCredentialKey(_) {
                    }
                }
            }
        )
    }

    private static func setProfileInvoke(
        api: AuthenticatedChatConnection,
        args: SetProfileArgs
    ) async throws -> ProfileDataHash {
        try await api.setProfileImpl(
            rng: args.rngSeed,
            aci: args.aci,
            profileKey: args.profileKey,
            profile: args.profile,
            expectedCurrentDataHash: args.expectedCurrentDataHash,
            expectedCurrentProfileKeyVersion: args.expectedCurrentProfileKeyVersion,
        )
    }
    private static func setProfileCheck(
        expected: SetProfileOut,
        actual: Result<ProfileDataHash, any Error>,
    ) throws {
        switch expected {
        case .success(let out):
            XCTAssertEqual(out, try actual.get())
        case .failure(let err):
            switch err {
            case .expectedDataWriteConflict:
                do {
                    _ = try actual.get()
                    XCTFail("Expected exception")
                } catch SignalError.setProfileExpectedDataWriteConflict(_) {
                }
            case .expectedVersionWriteConflict(let expectedProfileVersion):
                do {
                    _ = try actual.get()
                    XCTFail("Expected exception")
                } catch SignalError.setProfileExpectedVersionWriteConflict(
                    currentProfileVersion: let profileVersion,
                    message: _
                ) {
                    XCTAssertEqual(expectedProfileVersion?.serialize(), profileVersion?.serialize())
                }
            case .invalidProfile(let expectedValidationErrorInternal):
                do {
                    _ = try actual.get()
                    XCTFail("Expected exception")
                } catch SignalError.setProfileInvalidProfile(
                    profileValidationError: let validationError,
                    message: _
                ) {
                    let expectedValidationError: ProfileValidationError
                    switch expectedValidationErrorInternal {
                    case .fieldTooLong(let field, let len, let maxLen):
                        expectedValidationError = .fieldTooLong(field: field, len: Int(len), maxLen: Int(maxLen))
                    case .givenNameEmpty: expectedValidationError = .givenNameEmpty
                    }
                    XCTAssertEqual(validationError, expectedValidationError)
                }
            case .paymentsForbiddenInRegion:
                do {
                    _ = try actual.get()
                    XCTFail("Expected exception")
                } catch SignalError.setProfilePaymentsForbiddenInRegion(_) {
                }
            }
        }
    }

    func testSetProfile() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetProfileTests(),
            invoke: AuthProfilesServiceImplTests.setProfileInvoke,
            check: AuthProfilesServiceImplTests.setProfileCheck,
        )
    }

    func testSetProfileValidation() async throws {
        signal_testing_enable_deterministic_rng_for_testing()
        for test in try NativeTestingNice.TESTING_SetProfileValidationTests() {
            print(test.name)
            let api = self.api
            let request = test.request
            async let resultFuture = AuthProfilesServiceImplTests.setProfileInvoke(api: api, args: request)
            let result: Result<ProfileDataHash, any Error>
            do {
                result = .success(try await resultFuture)
            } catch {
                result = .failure(error)
            }
            try AuthProfilesServiceImplTests.setProfileCheck(expected: test.response, actual: result)
        }
    }

    func testProfileFieldWithMaxLength() throws {
        for (field, maxLength) in try NativeTestingNice.TESTING_ProfileFieldMaxLengths() {
            XCTAssertEqual(field.maxLength, Int(maxLength))
        }
    }
}

#endif

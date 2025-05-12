//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum RegistrationError: Error {
    case invalidSessionId(String)
    case requestNotValid(String)
    case notReadyForVerification(String)
    case sessionNotFound(String)
    case sendVerificationFailed(String)
    case codeNotDeliverable(message: String, permanentFailure: Bool)
    case sessionUpdateRejected(String)
    case credentialsCouldNotBeParsed(String)
    case unknown(String)
}

/// Client for the Signal registration service.
///
/// This wraps a ``Net`` to provide a reliable registration service client.
///
public class RegistrationService: NativeHandleOwner<SignalMutPointerRegistrationService> {
    private let asyncContext: TokioAsyncContext

    override internal class func destroyNativeHandle(_ nativeHandle: NonNull<SignalMutPointerRegistrationService>) -> SignalFfiErrorRef? {
        signal_registration_service_destroy(nativeHandle.pointer)
    }

    private init(owned: NonNull<SignalMutPointerRegistrationService>, asyncContext: TokioAsyncContext) {
        self.asyncContext = asyncContext
        super.init(owned: owned)
    }

    required init(owned: NonNull<SignalMutPointerRegistrationService>) {
        fatalError("must not be invoked directly")
    }

    /// Starts a new registration session.
    ///
    /// Asynchronously connects to the registration session and requests a new session.
    /// If successful, returns an initialized ``RegistrationService``. Otherwise an error is thrown.
    ///
    /// - Throws: On failure, throws one of
    ///   - ``RegistrationError`` if the request fails with a known error response.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    ///   - Some other `SignalError` if the request can't be completed.
    public static func createSession(
        _ net: Net,
        connectionTimeoutMillis: UInt32?,
        e164: String,
        pushToken: String?,
        mcc: String? = nil,
        mnc: String? = nil
    ) async throws -> RegistrationService {
        let connectChatBridge = SignalFfiConnectChatBridgeStruct.forManager(net.connectionManager)

        let service: SignalMutPointerRegistrationService =
            try await net.asyncContext.invokeAsyncFunction { promise, tokioContext in
                e164.withCString { e164 in
                    pushToken.withCString { pushToken in
                        mcc.withCString { mcc in
                            mnc.withCString { mnc in
                                let request = SignalFfiRegistrationCreateSessionRequest(
                                    number: e164, push_token: pushToken,
                                    mcc: mcc, mnc: mnc
                                )

                                return withUnsafePointer(to: connectChatBridge) { connectChatBridge in
                                    signal_registration_service_create_session(
                                        promise,
                                        tokioContext.const(),
                                        request,
                                        SignalConstPointerFfiConnectChatBridgeStruct(
                                            raw: connectChatBridge)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        return RegistrationService(owned: NonNull(service)!, asyncContext: net.asyncContext)
    }

    /// Resumes a previous registration session.
    ///
    /// Asynchronously connects to the registration session and requests a new session.
    /// If successful, returns an initialized ``RegistrationService``. Otherwise an error is thrown.
    ///
    /// - Throws: On failure, throws one of
    ///   - ``RegistrationError/sessionNotFound(_:)`` if the session can't be resumed.
    ///   - A different ``RegistrationError`` if the request fails with another known error response.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    ///   - Some other `SignalError` if the request can't be completed.
    public static func resumeSession(
        _ net: Net,
        connectionTimeoutMillis: UInt32?,
        sessionId: String,
        number: String
    ) async throws -> RegistrationService {
        let connectChatBridge = SignalFfiConnectChatBridgeStruct.forManager(net.connectionManager)

        let service: SignalMutPointerRegistrationService =
            try await net.asyncContext.invokeAsyncFunction { promise, tokioContext in
                withUnsafePointer(
                    to: connectChatBridge
                ) { connectChatBridge in
                    signal_registration_service_resume_session(
                        promise,
                        tokioContext.const(),
                        sessionId, number,
                        SignalConstPointerFfiConnectChatBridgeStruct(
                            raw: connectChatBridge)
                    )
                }
            }
        return RegistrationService(owned: NonNull(service)!)
    }

    /// Request a push challenge sent to the provided APN token.
    ///
    /// - Throws: On failure, throws one of
    ///   - ``RegistrationError`` if the request fails with a known error response.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    ///   - Some other `SignalError` if the request can't be completed.
    public func requestPushChallenge(apnPushToken: String) async throws {
        let _: Bool = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.withNativeHandle {
                signal_registration_service_request_push_challenge(promise, asyncContext.const(), $0.const(), apnPushToken, nil)
            }
        }
    }

    /// Submit the result of a push challenge.
    ///
    /// - Throws: On failure, throws one of
    ///   - ``RegistrationError`` if the request fails with a known error response.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    ///   - Some other `SignalError` if the request can't be completed.
    public func submitPushChallenge(pushChallenge: String) async throws {
        let _: Bool = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.withNativeHandle {
                signal_registration_service_submit_push_challenge(promise, asyncContext.const(), $0.const(), pushChallenge)
            }
        }
    }

    /// Request that a verification code be sent via the given transport method.
    /// Submit the result of a push challenge.
    ///
    /// - Throws: On failure, throws one of
    ///   - ``RegistrationError/sendVerificationFailed(message:permanentFailure:)`` if the code couldn't be sent.
    ///   - ``RegistrationError/codeNotDeliverable(_:)`` if the code couldn't be delivered.
    ///   - A different ``RegistrationError`` if the request fails with another known error response.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    ///   - Some other `SignalError` if the request can't be completed.
    public func requestVerificationCode(
        transport: VerificationTransport,
        client: String,
        languages: [String]
    ) async throws {
        let _: Bool = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            languages.withUnsafeBorrowedBytestringArray { languages in
                self.withNativeHandle {
                    signal_registration_service_request_verification_code(
                        promise, asyncContext.const(), $0.const(), transport.description,
                        client, languages
                    )
                }
            }
        }
    }

    /// Submit a received verification code.
    ///
    /// - Throws: On failure, throws one of
    ///   - ``RegistrationError/notReadyForVerification`` if uncompleted challenges remain.
    ///   - A different ``RegistrationError`` if the request fails with another known error response.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    ///   - Some other `SignalError` if the request can't be completed.
    public func submitVerificationCode(code: String) async throws {
        let _: Bool = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.withNativeHandle {
                signal_registration_service_submit_verification_code(
                    promise, asyncContext.const(), $0.const(), code
                )
            }
        }
    }

    /// Submit the result of a completed captcha challenge.
    ///
    /// - Throws: On failure, throws one of
    ///   - ``RegistrationError`` if the request fails with a recognized error response.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    ///   - Some other `SignalError` if the request can't be completed.
    public func submitCaptcha(captchaValue: String) async throws {
        let _: Bool = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.withNativeHandle {
                signal_registration_service_submit_verification_code(
                    promise, asyncContext.const(), $0.const(), captchaValue
                )
            }
        }
    }

    /// Check that the given list of SVR credentials is valid.
    ///
    /// # Return
    /// If the request succeeds, returns a map of submitted credential to check result.
    ///
    /// - Throws: On failure, throws one of
    ///   - ``RegistrationError`` if the request fails with a recognized error response.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    ///   - Some other `SignalError` if the request can't be completed.
    public func checkSvr2Credentials(svrTokens: [String]) async throws -> [String: Svr2CredentialsResult] {
        var result = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            svrTokens.withUnsafeBorrowedBytestringArray { svrTokens in
                self.withNativeHandle {
                    signal_registration_service_check_svr2_credentials(promise, asyncContext.const(), $0.const(), svrTokens)
                }
            }
        }
        return try invokeFnReturningCheckSvr2CredentialsResponse { out in
            out!.update(from: &result, count: 1)
            return nil
        }
    }

    /// The ID for this registration validation session.
    public var sessionId: String {
        return failOnError {
            try invokeFnReturningString { out in
                self.withNativeHandle {
                    signal_registration_service_session_id(out, $0.const())
                }
            }
        }
    }

    /// The session state received from the server with the last completed validation request.
    public var sessionState: RegistrationSessionState {
        return failOnError {
            try invokeFnReturningNativeHandle { out in
                self.withNativeHandle { nativeHandle in
                    signal_registration_service_registration_session(out, nativeHandle.const())
                }
            }
        }
    }
}

public class RegistrationSessionState: NativeHandleOwner<SignalMutPointerRegistrationSession> {
    override internal class func destroyNativeHandle(
        _ nativeHandle: NonNull<SignalMutPointerRegistrationSession>
    ) -> SignalFfiErrorRef? {
        signal_registration_session_destroy(nativeHandle.pointer)
    }

    public var allowedToRequestCode: Bool {
        return failOnError {
            try invokeFnReturningBool { out in
                self.withNativeHandle {
                    signal_registration_session_get_allowed_to_request_code(out, $0.const())
                }
            }
        }
    }

    public var verified: Bool {
        return failOnError {
            try invokeFnReturningBool { out in
                self.withNativeHandle {
                    signal_registration_session_get_verified(out, $0.const())
                }
            }
        }
    }

    public var nextSms: TimeInterval? {
        return failOnError {
            try invokeFnReturningOptionalInteger { out in
                self.withNativeHandle {
                    signal_registration_session_get_next_sms_seconds(out, $0.const())
                }
            }.map { TimeInterval($0) }
        }
    }

    public var nextCall: TimeInterval? {
        return failOnError {
            try invokeFnReturningOptionalInteger { out in
                self.withNativeHandle {
                    signal_registration_session_get_next_call_seconds(out, $0.const())
                }
            }.map { TimeInterval($0) }
        }
    }

    public var nextVerificationAttempt: TimeInterval? {
        return failOnError {
            try invokeFnReturningOptionalInteger { out in
                self.withNativeHandle {
                    signal_registration_session_get_next_verification_attempt_seconds(out, $0.const())
                }
            }.map { TimeInterval($0) }
        }
    }

    public var requestedInformation: Set<RequestedInformation> {
        return failOnError {
            let items = try invokeFnReturningArray { out in
                self.withNativeHandle {
                    signal_registration_session_get_requested_information(out, $0.const())
                }
            }
            return Set(try items.map {
                return switch UInt32($0) {
                case SignalRequestedInformationCaptcha.rawValue:
                    RequestedInformation.captcha
                case SignalRequestedInformationPushChallenge.rawValue:
                    RequestedInformation.pushChallenge
                default:
                    throw SignalError.internalError("unknown requested information")
                }
            })
        }
    }
}

public class RegisterAccountResponse: NativeHandleOwner<SignalMutPointerRegisterAccountResponse> {
    override internal class func destroyNativeHandle(_ nativeHandle: NonNull<SignalMutPointerRegisterAccountResponse>) -> SignalFfiErrorRef? {
        signal_register_account_response_destroy(nativeHandle.pointer)
    }

    public var aci: Aci {
        return failOnError {
            try self.withNativeHandle { native in
                try invokeFnReturningServiceId {
                    signal_register_account_response_get_identity($0, native.const(), ServiceIdKind.aci.rawValue)
                }
            }
        }
    }

    public var pni: Pni {
        return failOnError {
            try self.withNativeHandle { native in
                try invokeFnReturningServiceId {
                    signal_register_account_response_get_identity($0, native.const(), ServiceIdKind.pni.rawValue)
                }
            }
        }
    }

    public var number: String {
        return failOnError {
            try self.withNativeHandle { native in
                try invokeFnReturningString {
                    signal_register_account_response_get_number($0, native.const())
                }
            }
        }
    }

    public var usernameHash: [UInt8]? {
        return failOnError {
            try self.withNativeHandle { native in
                try invokeFnReturningOptionalArray {
                    signal_register_account_response_get_username_hash($0, native.const())
                }
            }
        }
    }

    public var usernameLinkHandle: UUID? {
        return failOnError {
            try self.withNativeHandle { native in
                try invokeFnReturningOptionalUuid {
                    signal_register_account_response_get_username_link_handle($0, native.const())
                }
            }
        }
    }

    public var storageCapable: Bool {
        return failOnError {
            try self.withNativeHandle { native in
                try invokeFnReturningBool {
                    signal_register_account_response_get_storage_capable($0, native.const())
                }
            }
        }
    }

    public var reregistration: Bool {
        return failOnError {
            try self.withNativeHandle { native in
                try invokeFnReturningBool {
                    signal_register_account_response_get_reregistration($0, native.const())
                }
            }
        }
    }

    public var entitlements: ([BadgeEntitlement], BackupEntitlement?) {
        return failOnError {
            try self.withNativeHandle { native in
                let badges = try invokeFnReturningBadgeEntitlementArray {
                    signal_register_account_response_get_entitlement_badges($0, native.const())
                }

                let backup = try BackupEntitlement(fromResponse: native.const())

                return (badges, backup)
            }
        }
    }
}

public struct BadgeEntitlement: Equatable {
    public let id: String
    public let visible: Bool
    public let expiration: TimeInterval
}

public struct BackupEntitlement: Equatable {
    public let expiration: TimeInterval
    public let level: UInt64
    public init(expiration: TimeInterval, level: UInt64) {
        self.expiration = expiration
        self.level = level
    }

    fileprivate init?(fromResponse native: SignalConstPointerRegisterAccountResponse) throws {
        let backupExpiration = try invokeFnReturningOptionalInteger {
            signal_register_account_response_get_entitlement_backup_expiration_seconds($0, native)
        }
        guard case .some(let expiration) = backupExpiration else {
            return nil
        }

        let level = try invokeFnReturningOptionalInteger {
            signal_register_account_response_get_entitlement_backup_level($0, native)
        }
        guard case .some(let level) = level else {
            return nil
        }
        self.init(expiration: TimeInterval(expiration), level: level)
    }
}

public enum VerificationTransport: CustomStringConvertible {
    case voice
    case sms

    public var description: String {
        return switch self {
        case .voice: "voice"
        case .sms: "sms"
        }
    }
}

public enum Svr2CredentialsResult {
    case match
    case noMatch
    case invalid
}

public enum RequestedInformation: Hashable {
    case captcha
    case pushChallenge
}

extension SignalFfiConnectChatBridgeStruct {
    /// Constructs a ``SignalFfiConnectChatBridgeStruct`` that uses the given
    /// ``ConnectionManager`` to create chat connections.
    ///
    /// The caller must ensure that ``Self/destroy`` is called, either manually
    /// or by passing the value into a bridge function that will do so.
    fileprivate static func forManager(_ connectionManager: ConnectionManager) -> Self {
        return SignalFfiConnectChatBridgeStruct(
            ctx: Unmanaged.passRetained(connectionManager).toOpaque(),
            get_connection_manager: { ctx in
                Unmanaged<ConnectionManager>.fromOpaque(ctx!).takeUnretainedValue()
                    .unsafeNativeHandle
            },
            destroy: { ctx in _ = Unmanaged<ConnectionManager>.fromOpaque(ctx!).takeRetainedValue()
            }
        )
    }
}

/// Invoke a function returning an unsigned integral result where `nil` is bridged as the maximum value.
///
/// Bridging `nil` as max isn't a convention we want to rely on generally. It's
/// true for the getters in this file, though, hence `fileprivate`.
private func invokeFnReturningOptionalInteger<Result: FixedWidthInteger & UnsignedInteger>(fn: (UnsafeMutablePointer<Result>?) -> SignalFfiErrorRef?) throws -> Result? {
    let output = try invokeFnReturningInteger(fn: fn)
    return if output == Result.max { nil } else { output }
}

private func invokeFnReturningBadgeEntitlementArray(fn: (_ out: UnsafeMutablePointer<SignalOwnedBufferOfFfiRegisterResponseBadge>) -> SignalFfiErrorRef?) throws -> [BadgeEntitlement] {
    var out = SignalOwnedBufferOfFfiRegisterResponseBadge()
    try checkError(fn(&out))
    defer { signal_free_list_of_register_response_badges(out) }

    return UnsafeBufferPointer(start: out.base, count: out.length).map {
        BadgeEntitlement(id: String(cString: $0.id), visible: $0.visible, expiration: TimeInterval($0.expiration_secs))
    }
}

// Exposed for testing.
internal func invokeFnReturningCheckSvr2CredentialsResponse(fn: (_ out: UnsafeMutablePointer<SignalFfiCheckSvr2CredentialsResponse>?) -> SignalFfiErrorRef?) throws -> [String: Svr2CredentialsResult] {
    let entries = try invokeFnReturningSomeBytestringArray(fn: { out in
        // This is just a named wrapper around a bytestring array.
        var wrapper = SignalFfiCheckSvr2CredentialsResponse()
        let err = fn(&wrapper)
        // Copy the wrapped pointer into the provided output. The outer function
        // will also take care of deallocating.
        if err == nil {
            out!.update(from: &wrapper.entries, count: 1)
        }
        return err
    }, transform: { view in
        // The format for entries is a UTF-8 key with the value as a single byte at the end.
        let key = String(decoding: view.dropLast(), as: Unicode.UTF8.self)
        let valueByte = UInt32(view.last!)
        let value = switch SignalSvr2CredentialsResult(valueByte) {
        case SignalSvr2CredentialsResultInvalid:
            Svr2CredentialsResult.invalid
        case SignalSvr2CredentialsResultMatch:
            Svr2CredentialsResult.match
        case SignalSvr2CredentialsResultNoMatch:
            Svr2CredentialsResult.noMatch
        default:
            fatalError("unknown SVR2 credentials result value \(valueByte)")
        }
        return (key, value)
    })

    return Dictionary(uniqueKeysWithValues: entries)
}

extension SignalMutPointerRegistrationService: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerRegistrationService

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        SignalConstPointerRegistrationService(raw: self.raw)
    }
}

extension SignalConstPointerRegistrationService: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalMutPointerRegistrationSession: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerRegistrationSession

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        SignalConstPointerRegistrationSession(raw: self.raw)
    }
}

extension SignalConstPointerRegistrationSession: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalMutPointerRegisterAccountResponse: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerRegisterAccountResponse

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        SignalConstPointerRegisterAccountResponse(raw: self.raw)
    }
}

extension SignalConstPointerRegisterAccountResponse: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

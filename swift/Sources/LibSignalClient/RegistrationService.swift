//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum RegistrationError: Error {
    case invalidSessionId(String)
    case requestNotValid(String)
    case unknown(String)
}

/// Client for the Signal registration service.
///
/// This wraps a ``Net`` to provide a reliable registration service client.
///
public class RegistrationService: NativeHandleOwner<SignalMutPointerRegistrationService> {
    override internal class func destroyNativeHandle(_ nativeHandle: NonNull<SignalMutPointerRegistrationService>) -> SignalFfiErrorRef? {
        signal_registration_service_destroy(nativeHandle.pointer)
    }

    /// Starts a new registration session.
    ///
    /// Asynchronously connects to the registration session and requests a new session.
    /// If successful, returns an initialized ``RegistrationService``. Otherwise an error is thrown.
    ///
    /// # Throws
    /// - ``RegistrationError`` if the request fails with a known error response.
    /// - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server requests a retry later.
    /// - Some other `SignalError` if the request can't be completed.
    public static func createSession(
        _ net: Net,
        connectionTimeoutMillis: UInt32?,
        e164: String,
        pushToken: String?,
        mcc: String? = nil,
        mnc: String? = nil
    ) async throws -> RegistrationService {
        let connectChatBridge = SignalFfiConnectChatBridgeStruct(
            ctx: Unmanaged.passRetained(net.connectionManager).toOpaque(),
            get_connection_manager: { ctx in
                Unmanaged<ConnectionManager>.fromOpaque(ctx!).takeUnretainedValue()
                    .unsafeNativeHandle
            },
            destroy: { ctx in _ = Unmanaged<ConnectionManager>.fromOpaque(ctx!).takeRetainedValue()
            }
        )

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
        return RegistrationService(owned: NonNull(service)!)
    }
}

extension SignalMutPointerRegistrationService: SignalMutPointer {
    public typealias ConstPointer = OpaquePointer?

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> OpaquePointer? {
        self.raw
    }
}

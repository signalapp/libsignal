//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol AuthMessagesService: Sendable {
    /// Get an attachment upload form
    ///
    /// - Throws:
    ///   - ``SignalError/uploadTooLarge(_:)`` if ``uploadSize`` is too large
    ///   - the standard Signal network errors
    func getUploadForm(uploadSize: UInt64) async throws -> UploadForm

    /// Sends a 1:1 unsealed message.
    ///
    /// - Throws:
    ///   - ``SignalError/mismatchedDevices(entries:message:)`` if the recipient devices specified
    ///     in `contents` are out of date in some way. This is not a "partial success" result; the
    ///     message has not been sent to anybody.
    ///   - ``SignalError/serviceIdNotFound(_:)`` if the destination account has been unregistered.
    ///   - ``SignalError/rateLimitChallengeError(token:options:retryAfter:message:)`` if a
    ///     challenge must be completed before sending this message.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server is rate limiting
    ///     this client. This is **retryable** after waiting the designated delay.
    ///   - ``SignalError/connectionFailed(_:)``, ``SignalError/ioError(_:)``, or
    ///     ``SignalError/webSocketError(_:)`` for networking failures before and during
    ///     communication with the server. These can be **automatically retried** (backoff
    ///     recommended).
    ///   - Other ``SignalError``s for networking issues. These can be manually retried, but some
    ///     may indicate a possible bug in libsignal.
    ///   - `CancellationError` if the request is cancelled before completing.
    ///
    /// - SeeAlso:
    ///   - ``MismatchedDeviceEntry``
    func sendMessage(
        to recipient: ServiceId,
        timestamp: UInt64,
        contents: [SingleOutboundUnsealedMessage],
        onlineOnly: Bool,
        urgent: Bool,
    ) async throws

    /// Sends a 1:1 message to linked devices.
    ///
    /// - Throws:
    ///   - ``SignalError/mismatchedDevices(entries:message:)`` if the recipient devices specified
    ///     in `contents` are out of date in some way. This is not a "partial success" result; the
    ///     message has not been sent to anybody.
    ///   - ``SignalError/rateLimitChallengeError(token:options:retryAfter:message:)`` if a
    ///     challenge must be completed before sending this message.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server is rate limiting
    ///     this client. This is **retryable** after waiting the designated delay.
    ///   - ``SignalError/connectionFailed(_:)``, ``SignalError/ioError(_:)``, or
    ///     ``SignalError/webSocketError(_:)`` for networking failures before and during
    ///     communication with the server. These can be **automatically retried** (backoff
    ///     recommended).
    ///   - Other ``SignalError``s for networking issues. These can be manually retried, but some
    ///     may indicate a possible bug in libsignal.
    ///   - `CancellationError` if the request is cancelled before completing.
    ///
    /// - SeeAlso:
    ///   - ``MismatchedDeviceEntry``
    func sendSyncMessage(
        timestamp: UInt64,
        contents: [SingleOutboundUnsealedMessage],
        urgent: Bool,
    ) async throws
}

extension AuthenticatedChatConnection: AuthMessagesService {
    public func getUploadForm(uploadSize: UInt64) async throws -> UploadForm {
        return try UploadForm(
            consuming: try await self.tokioAsyncContext
                .invokeAsyncFunction { promise, tokioAsyncContext in
                    withNativeHandle { chatService in
                        signal_authenticated_chat_connection_get_upload_form(
                            promise,
                            tokioAsyncContext.const(),
                            chatService.const(),
                            uploadSize,
                        )
                    }
                }
        )
    }

    public func sendMessage(
        to recipient: ServiceId,
        timestamp: UInt64,
        contents: [SingleOutboundUnsealedMessage],
        onlineOnly: Bool,
        urgent: Bool
    ) async throws {
        var deviceIds: [UInt32] = []
        var registrationIds: [UInt32] = []
        var messages: [SignalConstPointerCiphertextMessage] = []
        for next in contents {
            deviceIds.append(next.deviceId.uint32Value)
            registrationIds.append(next.registrationId)
            messages.append(next.contents.unsafeNativeHandle.const())
        }
        defer {
            // Make sure none of the CiphertextMessages are prematurely destroyed.
            extendLifetime(contents)
        }

        let _: Bool = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            try! withAllBorrowed(
                self,
                recipient,
                .slice(deviceIds),
                .slice(registrationIds),
                .slice(messages),
            ) { chatService, destination, deviceIds, registrationIds, messages in
                signal_authenticated_chat_connection_send_message(
                    promise,
                    tokioAsyncContext.const(),
                    chatService.const(),
                    destination,
                    timestamp,
                    deviceIds,
                    registrationIds,
                    messages,
                    onlineOnly,
                    urgent,
                )
            }
        }
    }

    public func sendSyncMessage(timestamp: UInt64, contents: [SingleOutboundUnsealedMessage], urgent: Bool) async throws
    {
        var deviceIds: [UInt32] = []
        var registrationIds: [UInt32] = []
        var messages: [SignalConstPointerCiphertextMessage] = []
        for next in contents {
            deviceIds.append(next.deviceId.uint32Value)
            registrationIds.append(next.registrationId)
            messages.append(next.contents.unsafeNativeHandle.const())
        }
        defer {
            // Make sure none of the CiphertextMessages are prematurely destroyed.
            extendLifetime(contents)
        }

        let _: Bool = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            try! withAllBorrowed(
                self,
                .slice(deviceIds),
                .slice(registrationIds),
                .slice(messages),
            ) { chatService, deviceIds, registrationIds, messages in
                signal_authenticated_chat_connection_send_sync_message(
                    promise,
                    tokioAsyncContext.const(),
                    chatService.const(),
                    timestamp,
                    deviceIds,
                    registrationIds,
                    messages,
                    urgent,
                )
            }
        }
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthMessagesService> {
    public static var attachments: Self { .init() }
}

//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol UnauthMessagesService: Sendable {
    /// Sends a multi-recipient message encrypted with Sealed Sender v2.
    ///
    /// Messages to accounts that have been unregistered will be dropped by the server and (if using
    /// ``MultiRecipientSendAuth/groupSend(_:)``) reported in the resulting
    /// ``MultiRecipientMessageResponse``.
    ///
    /// - Throws:
    ///   - ``SignalError/requestUnauthorized(_:)`` if `auth` is not valid for the recipients
    ///     specified in `payload`. (This cannot happen when `auth` is
    ///     ``MultiRecipientSendAuth/story``.)
    ///   - ``SignalError/mismatchedDevices(entries:message:)`` if the recipient devices specified
    ///     in `payload` are out of date in some way. This is not a "partial success" result; the
    ///     message has not been sent to anybody.
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
    ///   - ``sealedSenderMultiRecipientEncrypt(_:for:excludedRecipients:identityStore:sessionStore:context:)``
    ///   - ``MismatchedDeviceEntry``
    func sendMultiRecipientMessage(
        _ payload: Data,
        timestamp: UInt64,
        auth: MultiRecipientSendAuth,
        onlineOnly: Bool,
        urgent: Bool
    ) async throws -> MultiRecipientMessageResponse
}

public enum MultiRecipientSendAuth: Sendable {
    case story
    case groupSend(GroupSendFullToken)

    fileprivate func groupSendTokenOrNil() -> GroupSendFullToken? {
        switch self {
        case .story: nil
        case .groupSend(let token): token
        }
    }
}

/// Successful response for
/// ``UnauthMessagesService/sendMultiRecipientMessage(_:timestamp:auth:onlineOnly:urgent:)``.
///
/// When sending using ``MultiRecipientSendAuth/groupSend(_:)``, the server will report which
/// recipients are currently unregistered. For ``MultiRecipientSendAuth/story`` the list will always
/// be empty.
public struct MultiRecipientMessageResponse: Sendable {
    public var unregisteredIds: [ServiceId]
    public init(unregisteredIds: [ServiceId]) {
        self.unregisteredIds = unregisteredIds
    }
}

/// A failure sending to a recipient on account of not being up to date on their devices.
///
/// An entry in ``SignalError/mismatchedDevices(entries:message:)``. Each entry represents a
/// recipient that has either added, removed, or relinked some devices in their account (potentially
/// including their primary device), as represented by the ``missingDevices``, ``extraDevices``, and
/// ``staleDevices`` arrays, respectively. Handling the exception involves removing the "extra"
/// devices and establishing new sessions for the "missing" and "stale" devices.
public struct MismatchedDeviceEntry: Sendable {
    public var account: ServiceId
    public var missingDevices: [UInt32]
    public var extraDevices: [UInt32]
    public var staleDevices: [UInt32]

    public init(
        account: ServiceId,
        missingDevices: [UInt32] = [],
        extraDevices: [UInt32] = [],
        staleDevices: [UInt32] = []
    ) {
        self.account = account
        self.missingDevices = missingDevices
        self.extraDevices = extraDevices
        self.staleDevices = staleDevices
    }

    internal init(_ raw: SignalFfiMismatchedDevicesError) {
        self.account = try! ServiceId.parseFrom(fixedWidthBinary: raw.account)
        self.missingDevices = Array(
            UnsafeBufferPointer(start: raw.missing_devices.base, count: raw.missing_devices.length)
        )
        self.extraDevices = Array(UnsafeBufferPointer(start: raw.extra_devices.base, count: raw.extra_devices.length))
        self.staleDevices = Array(UnsafeBufferPointer(start: raw.stale_devices.base, count: raw.stale_devices.length))
    }
}

extension UnauthenticatedChatConnection: UnauthMessagesService {
    public func sendMultiRecipientMessage(
        _ payload: Data,
        timestamp: UInt64,
        auth: MultiRecipientSendAuth,
        onlineOnly: Bool,
        urgent: Bool
    ) async throws -> MultiRecipientMessageResponse {
        let rawResponse: SignalOwnedBufferOfServiceIdFixedWidthBinaryBytes = try await self.tokioAsyncContext
            .invokeAsyncFunction { promise, tokioAsyncContext in
                withNativeHandle { chatService in
                    payload.withUnsafeBorrowedBuffer { payload in
                        let authBuffer = auth.groupSendTokenOrNil()?.serialize() ?? Data()
                        return authBuffer.withUnsafeBorrowedBuffer { authBuffer in
                            signal_unauthenticated_chat_connection_send_multi_recipient_message(
                                promise,
                                tokioAsyncContext.const(),
                                chatService.const(),
                                payload,
                                timestamp,
                                authBuffer,
                                onlineOnly,
                                urgent
                            )
                        }
                    }
                }
            }
        defer { signal_free_list_of_service_ids(rawResponse) }
        return MultiRecipientMessageResponse(
            unregisteredIds: UnsafeBufferPointer(start: rawResponse.base, count: rawResponse.length)
                .map { try! ServiceId.parseFrom(fixedWidthBinary: $0) }
        )
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthMessagesService> {
    public static var messages: Self { .init() }
}

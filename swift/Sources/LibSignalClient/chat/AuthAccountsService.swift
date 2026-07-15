//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// An account's SVR key: the 32-byte root from which account-related secrets are derived.
///
/// This is the same key that ``AccountEntropyPool/deriveSvrKey(_:)`` produces. Signal clients
/// historically call these bytes the "master key"; libsignal calls it the SVR key. The two names
/// refer to the same value.
///
/// - SeeAlso: ``AuthAccountsService/setRegistrationLock(_:)``
public class SvrKey: ByteArray, @unchecked Sendable {
    public static let SIZE = 32

    /// Throws if `contents` is not ``SIZE`` (32) bytes.
    public required init(contents: Data) throws {
        try super.init(newContents: contents, expectedLength: Self.SIZE)
    }
}

public protocol AuthAccountsService: Sendable {
    /// Sets the registration lock for the authenticated account, given the account's SVR key.
    ///
    /// libsignal derives the registration lock token from the SVR key
    /// (`HMAC-SHA256(svrKey, "Registration Lock")`) and sends only that token; the SVR key itself
    /// never leaves the device.
    ///
    /// While the registration lock is set, re-registering the account's phone
    /// number requires proving knowledge of the token.
    ///
    /// Only the account's primary device may set a registration lock.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func setRegistrationLock(_ svrKey: SvrKey) async throws

    /// Sets whether the authenticated account may be discovered by phone number via the Contact
    /// Discovery Service (CDS).
    ///
    /// If `false`, other users must discover this account by other means (e.g. by username).
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func setDiscoverableByPhoneNumber(_ discoverable: Bool) async throws
}

extension AuthenticatedChatConnection: AuthAccountsService {
    public func setRegistrationLock(_ svrKey: SvrKey) async throws {
        return try await NativeNice.AuthenticatedChatConnection_set_registration_lock(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            svrKey: svrKey.serialize(),
        )
    }

    public func setDiscoverableByPhoneNumber(_ discoverable: Bool) async throws {
        return try await NativeNice.AuthenticatedChatConnection_set_discoverable_by_phone_number(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            discoverable: discoverable,
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthAccountsService> {
    public static var accounts: Self { .init() }
}

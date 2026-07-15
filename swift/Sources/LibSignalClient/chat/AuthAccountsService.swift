//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

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

    /// Removes any registration lock from the authenticated account.
    ///
    /// This also succeeds if the account has no registration lock set, so a caller retrying a
    /// removal sees the same result as the original call.
    ///
    /// Only the account's primary device may clear a registration lock.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func clearRegistrationLock() async throws

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

    public func clearRegistrationLock() async throws {
        return try await NativeNice.AuthenticatedChatConnection_clear_registration_lock(
            asyncContext: self.tokioAsyncContext,
            chat: self,
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

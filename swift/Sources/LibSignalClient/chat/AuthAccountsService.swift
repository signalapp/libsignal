//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// The user-specified metadata attached to a multi-factor authentication (MFA) key, such as a TOTP
/// key, on the account.
///
/// This is stored encrypted on the server, so only the account's own devices can read it.
public struct MfaMetadata: Sendable, Equatable {
    /// The maximum length of ``name``, in UTF-8 bytes.
    public static let nameMaxLength = 98

    /// A human-readable name for the key, at most ``nameMaxLength`` bytes when encoded as UTF-8
    /// and not containing U+0000.
    public var name: String
    /// When the key was created.
    ///
    /// Stored with one-second granularity, so a value read back from the server may be truncated
    /// relative to the value that was written. Must not be before the Unix epoch.
    public var createdAt: Date

    public init(name: String, createdAt: Date) {
        self.name = name
        self.createdAt = createdAt
    }

    internal static func fromInternal(_ it: BridgeMfaMetadata) -> MfaMetadata {
        MfaMetadata(name: it.name, createdAt: it.createdAt)
    }
}

/// The parameters a TOTP generator needs, besides the key itself, to produce one-time passwords
/// the server will accept.
public struct TotpParameters: Sendable, Equatable {
    /// The HMAC algorithm (e.g. "HmacSHA256") used by the TOTP generator.
    public var algorithm: String
    /// The length of one-time passwords (in decimal digits) produced and expected by the TOTP
    /// generator.
    public var passwordLength: Int
    /// The time step used by the TOTP generator.
    public var timeStep: TimeInterval

    public init(algorithm: String, passwordLength: Int, timeStep: TimeInterval) {
        self.algorithm = algorithm
        self.passwordLength = passwordLength
        self.timeStep = timeStep
    }

    internal static func fromInternal(_ it: BridgeTotpParameters) -> TotpParameters {
        TotpParameters(
            algorithm: it.algorithm,
            passwordLength: Int(it.passwordLength),
            timeStep: TimeInterval(it.timeStepSeconds),
        )
    }
}

/// A newly-generated TOTP key that is not yet active.
///
/// Returned by ``AuthAccountsService/generateTotpKey()``; the key only starts being accepted for
/// the account once it is confirmed via
/// ``AuthAccountsService/confirmTotpKey(oneTimePassword:metadata:svrKey:)``.
public struct PendingTotpKey: Sendable, Equatable {
    /// The raw TOTP key.
    public var key: Data
    /// The TOTP parameters associated with the generated key.
    public var parameters: TotpParameters

    public init(key: Data, parameters: TotpParameters) {
        self.key = key
        self.parameters = parameters
    }

    internal static func fromInternal(_ it: BridgePendingTotpKey) -> PendingTotpKey {
        PendingTotpKey(
            key: it.key,
            parameters: TotpParameters.fromInternal(it.parameters),
        )
    }
}

/// The kind of a confirmed MFA key.
public enum MfaKeyKind: Sendable, Equatable {
    /// A TOTP key; see ``AuthAccountsService/generateTotpKey()``.
    case totp
    /// A kind of key this version of libsignal doesn't know about; see
    /// ``AuthAccountsService/listMfaKeys(svrKey:)``.
    case unknown

    internal static func fromInternal(_ it: BridgeMfaKeyKind) -> MfaKeyKind {
        switch it {
        case .totp: .totp
        case .unknown: .unknown
        }
    }
}

/// A confirmed multi-factor authentication (MFA) key on the account, as returned by
/// ``AuthAccountsService/listMfaKeys(svrKey:)``.
public struct ConfirmedMfaKey: Sendable, Equatable {
    /// The account-specific identifier for this key.
    public var id: Int
    /// The user-specified name and creation time attached to this key, or `nil` if it could not be
    /// decrypted with the provided SVR key; see ``AuthAccountsService/listMfaKeys(svrKey:)``.
    public var metadata: MfaMetadata?
    /// What kind of MFA key this is.
    public var kind: MfaKeyKind

    public init(id: Int, metadata: MfaMetadata?, kind: MfaKeyKind) {
        self.id = id
        self.metadata = metadata
        self.kind = kind
    }

    internal static func fromInternal(_ it: BridgeConfirmedMfaKey) -> ConfirmedMfaKey {
        let metadata: MfaMetadata? =
            switch it.metadata {
            case .metadata(let metadata): MfaMetadata.fromInternal(metadata)
            case .unreadable: nil
            }
        return ConfirmedMfaKey(
            id: Int(it.id),
            metadata: metadata,
            kind: MfaKeyKind.fromInternal(it.kind),
        )
    }
}

public protocol AuthAccountsService: Sendable {
    /// Deletes the authenticated account, purging all associated data in the
    /// process.
    ///
    /// Only the account's primary device may delete the account.
    ///
    /// Deleting the account also invalidates its connections, so the response
    /// can race the resulting disconnect. If the connection is interrupted
    /// before a response arrives, the deletion may nevertheless have taken
    /// effect; callers should not treat a transport error as proof the account
    /// still exists.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func deleteAccount() async throws

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

    /// Sets the registration recovery password for the authenticated account, given the account's
    /// SVR key.
    ///
    /// libsignal derives the registration recovery password from the SVR key
    /// (`HMAC-SHA256(svrKey, "Registration Recovery")`) and sends only that derived password; the
    /// SVR key itself never leaves the device.
    ///
    /// The registration recovery password lets the account re-register its phone
    /// number without SMS verification. Any of the account's devices may set it.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func setRegistrationRecoveryPassword(_ svrKey: SvrKey) async throws

    /// Sets whether the authenticated account may be discovered by phone number via the Contact
    /// Discovery Service (CDS).
    ///
    /// If `false`, other users must discover this account by other means (e.g. by username).
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func setDiscoverableByPhoneNumber(_ discoverable: Bool) async throws

    /// Generates and stores a new pending TOTP key for the authenticated account.
    ///
    /// The key is generated by the server and returned along with the parameters a TOTP generator
    /// needs to derive one-time passwords from it.
    ///
    /// The key does not become active until the client calls
    /// ``confirmTotpKey(oneTimePassword:metadata:svrKey:)`` to prove it can generate one-time
    /// passwords using the new key. The caller has 24 hours to confirm the key after it has been
    /// generated. This is the only time the key material for this TOTP key is available; if it is
    /// lost, a new one will need to be generated.
    ///
    /// - Throws:
    ///   - ``SignalError/tooManyTotpKeys(_:)`` if the account already has too many TOTP keys, and
    ///     one must be removed before adding more
    ///   - ``SignalError/tooManyMfaKeys(_:)`` if the account already has too many MFA keys of all
    ///     kinds, and one must be removed before adding more
    ///   - the standard Signal network errors
    func generateTotpKey() async throws -> PendingTotpKey

    /// Confirms the account's pending TOTP key (see ``generateTotpKey()``), thus activating it.
    ///
    /// A TOTP key must be confirmed within 24 hours of its generation.
    ///
    /// - Parameters:
    ///   - oneTimePassword: A one-time password derived from the pending key. This should be
    ///     provided by the user from their TOTP app, proving they have stored the key and can
    ///     correctly generate passwords from it going forward.
    ///   - metadata: Metadata (name, creation time) to attach to the newly-confirmed key; stored
    ///     encrypted, so that it may not be read by the server
    ///   - svrKey: The account's SVR key
    /// - Returns: The account-specific identifier assigned to the newly-confirmed key
    /// - Throws:
    ///   - ``SignalError/oneTimePasswordNotVerified(_:)`` if the one-time password was not
    ///     accepted for any reason
    ///   - ``SignalError/tooManyMfaKeys(_:)`` if the account filled up with MFA keys between
    ///     generating and confirming this one
    ///   - ``SignalError/invalidArgument(_:)`` if any of the arguments are invalid, such as if
    ///     the metadata's name exceeds ``MfaMetadata/nameMaxLength`` bytes of UTF-8 or contains
    ///     U+0000, its creation date is not valid, or `oneTimePassword` is not in legal range per
    ///     the RFC.
    ///   - the standard Signal network errors
    func confirmTotpKey(
        oneTimePassword: Int,
        metadata: MfaMetadata,
        svrKey: SvrKey
    ) async throws -> Int

    /// Lists the confirmed MFA keys for the authenticated account.
    ///
    /// An item with a `nil` ``ConfirmedMfaKey/metadata`` indicates that the metadata attached to
    /// that key could not be decrypted with the provided ``SvrKey`` (e.g. because the SVR key /
    /// AEP has rotated since the key was stored). If the user recalls the name for the key, this
    /// state is recoverable by calling ``setMfaKeyMetadata(for:metadata:svrKey:)``; otherwise,
    /// the key with the unreadable name may be removed by calling ``removeMfaKey(id:)``.
    ///
    /// Similarly, a key of a kind this version of libsignal doesn't recognize is still listed,
    /// with ``MfaKeyKind/unknown`` (e.g. because it was added from a linked device running a newer
    /// version of Signal).
    ///
    /// Pending (unconfirmed) keys are not included, and the key material itself is never
    /// returned.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func listMfaKeys(svrKey: SvrKey) async throws -> [ConfirmedMfaKey]

    /// Replaces the metadata attached to the confirmed MFA key identified by `keyId`.
    ///
    /// - Throws:
    ///   - ``SignalError/mfaKeyNotFound(_:)`` if no confirmed MFA key with the provided
    ///     identifier was found on the account
    ///   - ``SignalError/invalidArgument(_:)`` if `keyId` is outside the range of identifiers the
    ///     server assigns, the metadata's name exceeds ``MfaMetadata/nameMaxLength`` bytes of
    ///     UTF-8 or contains U+0000, or its creation date is non-finite, before the Unix epoch, or
    ///     too large to represent in milliseconds (programmer errors)
    ///   - the standard Signal network errors
    func setMfaKeyMetadata(for keyId: Int, metadata: MfaMetadata, svrKey: SvrKey) async throws

    /// Removes the MFA key identified by `keyId` from the authenticated account.
    ///
    /// This is idempotent; removing a key ID that is not on the account also succeeds.
    ///
    /// - Throws:
    ///   - ``SignalError/invalidArgument(_:)`` if `keyId` is outside the range of identifiers the
    ///     server assigns (a programmer error)
    ///   - the standard Signal network errors
    func removeMfaKey(id keyId: Int) async throws
}

extension AuthenticatedChatConnection: AuthAccountsService {
    public func deleteAccount() async throws {
        return try await NativeNice.AuthenticatedChatConnection_delete_account(
            asyncContext: self.tokioAsyncContext,
            chat: self,
        )
    }

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

    public func setRegistrationRecoveryPassword(_ svrKey: SvrKey) async throws {
        return try await NativeNice.AuthenticatedChatConnection_set_registration_recovery_password(
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

    public func generateTotpKey() async throws -> PendingTotpKey {
        return PendingTotpKey.fromInternal(
            try await NativeNice.AuthenticatedChatConnection_generate_totp_key(
                asyncContext: self.tokioAsyncContext,
                chat: self,
            )
        )
    }

    public func confirmTotpKey(
        oneTimePassword: Int,
        metadata: MfaMetadata,
        svrKey: SvrKey
    ) async throws -> Int {
        return try await self.confirmTotpKey(
            oneTimePassword: oneTimePassword,
            metadata: metadata,
            svrKey: svrKey,
            rngForTesting: -1,
        )
    }

    public func listMfaKeys(svrKey: SvrKey) async throws -> [ConfirmedMfaKey] {
        return try await NativeNice.AuthenticatedChatConnection_list_mfa_keys(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            svrKey: svrKey.serialize(),
        ).map { ConfirmedMfaKey.fromInternal($0) }
    }

    public func setMfaKeyMetadata(for keyId: Int, metadata: MfaMetadata, svrKey: SvrKey) async throws {
        return try await self.setMfaKeyMetadata(
            for: keyId,
            metadata: metadata,
            svrKey: svrKey,
            rngForTesting: -1,
        )
    }

    public func removeMfaKey(id keyId: Int) async throws {
        return try await NativeNice.AuthenticatedChatConnection_remove_mfa_key(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            keyId: try bridgeInt32(keyId, "keyId"),
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthAccountsService> {
    public static var accounts: Self { .init() }
}

internal protocol AuthAccountsServiceImpl: Sendable {
    func confirmTotpKey(
        oneTimePassword: Int,
        metadata: MfaMetadata,
        svrKey: SvrKey,
        rngForTesting: Int64,
    ) async throws -> Int

    func setMfaKeyMetadata(
        for keyId: Int,
        metadata: MfaMetadata,
        svrKey: SvrKey,
        rngForTesting: Int64,
    ) async throws
}

/// Converts an app-facing integer to the `Int32` the bridge uses (because Java has no
/// unsigned types), throwing ``SignalError/invalidArgument(_:)`` instead of trapping if it doesn't
/// fit. The Rust side does the real range checking; this just keeps out-of-range values from
/// crashing before they get there.
private func bridgeInt32(_ value: Int, _ name: String) throws -> Int32 {
    guard let converted = Int32(exactly: value) else {
        throw SignalError.invalidArgument("\(name) must be non-negative and fit in 31 bits (got \(value))")
    }
    return converted
}

/// Validates a date before the generated bridge converts it to unsigned milliseconds.
private func bridgeTimestamp(_ value: Date, _ name: String) throws -> Date {
    let milliseconds = value.timeIntervalSince1970 * 1000.0
    guard
        milliseconds.isFinite,
        milliseconds >= 0,
        UInt64(exactly: milliseconds.rounded(.towardZero)) != nil
    else {
        throw SignalError.invalidArgument(
            "\(name) must be representable as non-negative milliseconds since the Unix epoch"
        )
    }
    return value
}

/// Validates an MFA key name before the generated bridge converts it to a C string, which cannot
/// represent an embedded U+0000.
private func bridgeMfaKeyName(_ value: String) throws -> String {
    guard !value.contains("\0") else {
        throw SignalError.invalidArgument("metadata.name must not contain U+0000")
    }
    return value
}

extension AuthenticatedChatConnection: AuthAccountsServiceImpl {
    func confirmTotpKey(
        oneTimePassword: Int,
        metadata: MfaMetadata,
        svrKey: SvrKey,
        rngForTesting: Int64,
    ) async throws -> Int {
        let keyId = try await NativeNice.AuthenticatedChatConnection_confirm_totp_key(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            oneTimePassword: try bridgeInt32(oneTimePassword, "oneTimePassword"),
            name: try bridgeMfaKeyName(metadata.name),
            createdAt: try bridgeTimestamp(metadata.createdAt, "metadata.createdAt"),
            svrKey: svrKey.serialize(),
            rng: rngForTesting,
        )
        return Int(keyId)
    }

    func setMfaKeyMetadata(
        for keyId: Int,
        metadata: MfaMetadata,
        svrKey: SvrKey,
        rngForTesting: Int64,
    ) async throws {
        return try await NativeNice.AuthenticatedChatConnection_set_mfa_key_metadata(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            keyId: try bridgeInt32(keyId, "keyId"),
            name: try bridgeMfaKeyName(metadata.name),
            createdAt: try bridgeTimestamp(metadata.createdAt, "metadata.createdAt"),
            svrKey: svrKey.serialize(),
            rng: rngForTesting,
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthAccountsServiceImpl> {
    internal static var accountsImpl: Self { .init() }
}

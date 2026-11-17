//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public typealias ProfileDataHash = Data
public typealias PaymentAddress = Data
public typealias BadgeId = String
public typealias ProfileEtag = Data
public typealias CdnUrl = String

/// The result of fetching a profile.
///
/// This contains the profile, itself, along with other associated information
/// about the target account.
public struct FetchedProfile: Sendable, Equatable {
    public init(
        profile: Profile,
        etag: ProfileEtag? = nil,
        v2DataHash: Data? = nil,
        identityKey: IdentityKey,
        unidentifiedAccessKeyFingerprint: Data? = nil,
        unrestrictedUnidentifiedAccess: Bool
    ) {
        self.profile = profile
        self.etag = etag
        self.v2DataHash = v2DataHash
        self.identityKey = identityKey
        self.unidentifiedAccessKeyFingerprint = unidentifiedAccessKeyFingerprint
        self.unrestrictedUnidentifiedAccess = unrestrictedUnidentifiedAccess
    }

    public var profile: Profile
    /// What's the etag of this profile?
    ///
    /// It may be `nil`if the profile isn't cacheable (i.e. if it's not a v2 profile)
    public var etag: ProfileEtag?
    /// If the account has a v2 profile set, what's its data hash?
    public var v2DataHash: ProfileDataHash?
    public var identityKey: IdentityKey
    /// This should only be `nil` if `unidentifiedAccessKeyFingerprint` is true
    public var unidentifiedAccessKeyFingerprint: Data?
    public var unrestrictedUnidentifiedAccess: Bool
}

public struct Profile: Sendable, Equatable {
    public init(
        givenName: String,
        familyName: String,
        about: String,
        aboutEmoji: String,
        avatar: CdnUrl? = nil,
        phoneNumberSharing: Bool?,
        paymentAddress: PaymentAddress? = nil,
        badgeIds: [BadgeId]
    ) {
        self.givenName = givenName
        self.familyName = familyName
        self.about = about
        self.aboutEmoji = aboutEmoji
        self.avatar = avatar
        self.phoneNumberSharing = phoneNumberSharing
        self.paymentAddress = paymentAddress
        self.badgeIds = badgeIds
    }

    /// Optional (can be empty); max-length is 128 bytes
    public var givenName: String
    /// Optional (can be empty); max-length is 128 bytes
    public var familyName: String
    /// Optional (can be empty); max-length is 512 bytes
    public var about: String
    /// Optional (can be empty); max-length is 32 bytes
    public var aboutEmoji: String
    /// If provided, it must be the full URL to the avatar.
    ///
    /// The URL must point to a Signal CDN server. (This will be validated on outgoing and incoming
    /// profiles.)
    public var avatar: CdnUrl?
    // The following fields are conceptually part of the user's profile, but live outside of the
    // encrypted v2 PlaintextProfileData
    /// phoneNumberSharing is allowed to be `nil` on _incoming_ profiles for backwards compatibility
    /// (`nil` indicates that phoneNumberSharing is in an indeterminate for the account)
    /// `setProfile()` will raise an error on an attempt to set this to `nil` on outgoing profiles
    public var phoneNumberSharing: Bool?
    public var paymentAddress: PaymentAddress?
    public var badgeIds: [BadgeId]
}

public enum ProfileFieldWithMaxLength: Sendable, Equatable {
    case givenName
    case familyName
    case about
    case aboutEmoji
    case avatar
    case paymentAddress

    public var maxLength: Int {
        switch self {
        case .about: return 512
        case .aboutEmoji: return 32
        case .avatar: return 128
        case .familyName: return 128
        case .givenName: return 128
        case .paymentAddress: return 550
        }
    }
}

public enum ProfileValidationError: Sendable, Equatable {
    case fieldTooLong(field: ProfileFieldWithMaxLength, len: Int, maxLen: Int)
    case avatarUrlInvalid
}

public class AvatarCdnUrlValidationConfig: NativeHandleOwner<SignalMutPointerAvatarCdnUrlValidationConfig> {

    /// URL prefixes must:
    /// 1. Start with `http://` or `https://`
    /// 2. end with a `/`
    ///
    /// - Throws:
    ///   - ``SignalError/internalError(_:)`` if the prefixes are invalid
    public static func fromUrlPrefixes(_ validUrlPrefixes: [String]) throws -> AvatarCdnUrlValidationConfig {
        return try NativeNice.AvatarCdnUrlValidationConfig_new(validUrlPrefixes: validUrlPrefixes)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerAvatarCdnUrlValidationConfig>
    ) -> SignalFfiErrorRef? {
        return signal_avatar_cdn_url_validation_config_destroy(handle.pointer)
    }
}

extension SignalMutPointerAvatarCdnUrlValidationConfig: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerAvatarCdnUrlValidationConfig

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerAvatarCdnUrlValidationConfig: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

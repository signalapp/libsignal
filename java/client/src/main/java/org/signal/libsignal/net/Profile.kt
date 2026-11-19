//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.ObjectHandle
import org.signal.libsignal.protocol.IdentityKey

public typealias BadgeId = String
public typealias PaymentAddress = ByteArray
public typealias ProfileDataHash = ByteArray
public typealias ProfileEtag = ByteArray
public typealias CdnUrl = String

/**
 *  The result of fetching a profile.
 *
 *  This contains the profile, itself, along with other associated information
 *  about the target account.
 */
public data class FetchedProfile(
  public val profile: Profile,
  /**
   * What's the etag of this profile?
   *
   * It may be null if the profile isn't cacheable (i.e. if it's not a v2
   * profile).
   */
  public val etag: ProfileEtag?,
  /**
   * If the account has a v2 profile set, what's its data hash?
   */
  public val v2DataHash: ProfileDataHash?,
  public val identityKey: IdentityKey,
  /**
   * This should only be null if unrestrictedUnidentifiedAccess is true
   */
  public val unidentifiedAccessKeyFingerprint: ByteArray?,
  public val unrestrictedUnidentifiedAccess: Boolean,
) {
  // Because there are ByteArray fields
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as FetchedProfile

    if (unrestrictedUnidentifiedAccess != other.unrestrictedUnidentifiedAccess) return false
    if (profile != other.profile) return false
    if (!etag.contentEquals(other.etag)) return false
    if (!v2DataHash.contentEquals(other.v2DataHash)) return false
    if (identityKey != other.identityKey) return false
    if (!unidentifiedAccessKeyFingerprint.contentEquals(other.unidentifiedAccessKeyFingerprint)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = unrestrictedUnidentifiedAccess.hashCode()
    result = 31 * result + profile.hashCode()
    result = 31 * result + (etag?.contentHashCode() ?: 0)
    result = 31 * result + (v2DataHash?.contentHashCode() ?: 0)
    result = 31 * result + identityKey.hashCode()
    result = 31 * result + (unidentifiedAccessKeyFingerprint?.contentHashCode() ?: 0)
    return result
  }
}

@Suppress("ktlint:standard:no-consecutive-comments")
public data class Profile(
  /**
   * Optional (can be empty); max-length is 128 bytes
   */
  public val givenName: String,
  /**
   * Optional (can be empty); max-length is 128 bytes
   */
  public val familyName: String,
  /**
   * Optional (can be empty); max-length is 512 bytes
   */
  public val about: String,
  /**
   * Optional (can be empty); max-length is 32 bytes
   */
  public val aboutEmoji: String,
  /**
   * If provided, it must be the full URL to the avatar.
   *
   * The URL must point to a Signal CDN server. (This will be validated on outgoing and incoming
   * profiles.)
   */
  public val avatar: CdnUrl?,
  // The following fields are conceptually part of the user's profile, but live outside of the
  // encrypted v2 PlaintextProfileData
  /**
   * phoneNumberSharing is allowed to be null on _incoming_ profiles for backwards compatibility
   * (null indicates that phoneNumberSharing is in an indeterminate state for the account)
   * setProfile() will raise an error on an attempt to set this to null on outgoing profiles
   */
  public val phoneNumberSharing: Boolean?,
  public val paymentAddress: PaymentAddress?,
  public val badgeIds: List<BadgeId>,
) {
  // Generated equals+hashCode() due to ByteArray
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as Profile

    if (phoneNumberSharing != other.phoneNumberSharing) return false
    if (givenName != other.givenName) return false
    if (familyName != other.familyName) return false
    if (about != other.about) return false
    if (aboutEmoji != other.aboutEmoji) return false
    if (avatar != other.avatar) return false
    if (!paymentAddress.contentEquals(other.paymentAddress)) return false
    if (badgeIds != other.badgeIds) return false

    return true
  }

  override fun hashCode(): Int {
    var result = phoneNumberSharing.hashCode()
    result = 31 * result + givenName.hashCode()
    result = 31 * result + familyName.hashCode()
    result = 31 * result + about.hashCode()
    result = 31 * result + aboutEmoji.hashCode()
    result = 31 * result + avatar.hashCode()
    result = 31 * result + (paymentAddress?.contentHashCode() ?: 0)
    result = 31 * result + badgeIds.hashCode()
    return result
  }
}

public class AvatarCdnUrlValidationConfig internal constructor(
  nativeHandle: ObjectHandle,
) : NativeHandleGuard.SimpleOwner(
    NativeHandleGuard.SimpleOwner.throwIfNull(nativeHandle),
  ) {
  public companion object {
    /**
     * URL prefixes must:
     * 1. Start with `http://` or `https://`
     * 2. end with a `/`
     *
     * @throws AssertionError if these constraints are validated
     */
    public fun fromUrlPrefixes(validUrlPrefixes: List<String>): AvatarCdnUrlValidationConfig =
      NativeNice.AvatarCdnUrlValidationConfig_new(validUrlPrefixes = validUrlPrefixes)
  }

  protected override fun release(nativeHandle: ObjectHandle) {
    Native.AvatarCdnUrlValidationConfig_Destroy(nativeHandle)
  }
}

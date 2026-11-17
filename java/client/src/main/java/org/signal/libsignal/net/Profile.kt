//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.protocol.IdentityKey

public typealias BadgeId = String
public typealias PaymentAddress = ByteArray
public typealias ProfileDataHash = ByteArray
public typealias ProfileEtag = ByteArray

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

public data class Profile(
  /**
   * Non-empty; max-length is 128 bytes
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
  public val avatar: CdnUrl?,
  // The following fields are conceptually part of the user's profile, but live outside of the
  // encrypted v2 PlaintextProfileData
  public val phoneNumberSharing: Boolean,
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

/**
 * A URL that points to a Signal CDN
 */
@ConsistentCopyVisibility
public data class CdnUrl private constructor(
  public val url: String,
) {
  public companion object {
    // Public only for testing
    public fun libsignalOnlyFromPreValidatedString(url: String): CdnUrl = CdnUrl(url)

    /**
     * @throws IllegalArgumentException if the URL doesn't point at a Signal CDN
     */
    public fun fromString(url: String): CdnUrl {
      if (!NativeNice.CdnUrl_validate(url)) throw IllegalArgumentException("Illegal CDN URL")
      return CdnUrl(url)
    }
  }
}

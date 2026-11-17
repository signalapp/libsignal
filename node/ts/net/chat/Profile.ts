//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';
import type * as EcKeys from '../../EcKeys.js';
import * as Native from '../../Native.js';

export type BadgeId = string;
export type PaymentAddress = Bytes;
export type ProfileDataHash = Bytes;
export type ProfileEtag = Bytes;
export type CdnUrl = string;

export class AvatarCdnUrlValidationConfig {
  readonly _nativeHandle: Native.AvatarCdnUrlValidationConfig;

  private constructor(handle: Native.AvatarCdnUrlValidationConfig) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    handle: Native.AvatarCdnUrlValidationConfig
  ): AvatarCdnUrlValidationConfig {
    return new AvatarCdnUrlValidationConfig(handle);
  }

  /**
   * URL prefixes must:
   * 1. Start with `http://` or `https://`
   * 2. end with a `/`
   *
   * @throws an internal error if these constraints are validated
   */
  public static fromUrlPrefixes(
    validUrlPrefixes: string[]
  ): AvatarCdnUrlValidationConfig {
    return AvatarCdnUrlValidationConfig._fromNativeHandle(
      Native.AvatarCdnUrlValidationConfig_new(validUrlPrefixes)
    );
  }
}

export type Profile = {
  /**
   * Optional (can be empty); max-length is 128 bytes
   */
  givenName: string;
  /**
   * Optional (can be empty); max-length is 128 bytes
   */
  familyName: string;
  /**
   * Optional (can be empty); max-length is 512 bytes
   */
  about: string;
  /**
   * Optional (can be empty); max-length is 32 bytes
   */
  aboutEmoji: string;
  /**
   * If provided, it must be the full URL to the avatar.
   *
   * The URL must point to a Signal CDN server. (This will be validated on outgoing and incoming
   * profiles.)
   */
  avatar: CdnUrl | null;
  // The following fields are conceptually part of the user's profile, but live outside of the
  // encrypted v2 PlaintextProfileData
  /**
   * phoneNumberSharing is allowed to be null on _incoming_ profiles for
   * backwards compatibility. (null indicates that phoneNumberSharing is in an
   * indeterminate state for the account).
   * setProfile() will raise an error on an attempt to set this to null on
   * outgoing profiles.
   */
  phoneNumberSharing: boolean | null;
  paymentAddress: PaymentAddress | null;
  badgeIds: Array<BadgeId>;
};

/**
 *  The result of fetching a profile.
 *
 *  This contains the profile, itself, along with other associated information
 *  about the target account.
 */
export type FetchedProfile = {
  profile: Profile;
  /**
   * What's the etag of this profile?
   *
   * It may be null if the profile isn't cacheable (i.e. if it's not a v2
   * profile).
   */
  etag: ProfileEtag | null;
  /**
   * If the account has a v2 profile set, what's its data hash?
   */
  v2DataHash: ProfileDataHash | null;
  identityKey: EcKeys.PublicKey;
  /**
   * This should only be null if unrestrictedUnidentifiedAccess is true
   */
  unidentifiedAccessKeyFingerprint: Bytes | null;
  unrestrictedUnidentifiedAccess: boolean;
};

export type ProfileFieldWithMaxLength =
  | 'givenName'
  | 'familyName'
  | 'about'
  | 'aboutEmoji'
  | 'avatar'
  | 'paymentAddress';

export const PROFILE_FIELD_MAX_LENGTHS: Record<
  ProfileFieldWithMaxLength,
  number
> = {
  givenName: 128,
  familyName: 128,
  about: 512,
  aboutEmoji: 32,
  avatar: 128,
  paymentAddress: 550,
};

export type ProfileValidationError =
  | {
      fieldTooLong: {
        field: ProfileFieldWithMaxLength;
        len: number;
        maxLen: number;
      };
    }
  | 'avatarUrlInvalid';

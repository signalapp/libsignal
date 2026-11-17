//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { CdnUrl } from './CdnUrl.js';
import type { Bytes } from '@signalapp/types';

export type BadgeId = string;
export type PaymentAddress = Bytes;
export type ProfileDataHash = Bytes;

export type Profile = {
  /**
   * Non-empty; max-length is 128 bytes
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
  avatar: CdnUrl | null;
  // The following fields are conceptually part of the user's profile, but live outside of the
  // encrypted v2 PlaintextProfileData
  phoneNumberSharing: boolean;
  paymentAddress: PaymentAddress | null;
  badgeIds: Array<BadgeId>;
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
  | 'givenNameEmpty';

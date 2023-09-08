//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import ProfileKeyCommitment from './ProfileKeyCommitment';
import ProfileKeyVersion from './ProfileKeyVersion';
import { Aci } from '../../Address';

export default class ProfileKey extends ByteArray {
  private readonly __type?: never;
  static SIZE = 32;

  constructor(contents: Buffer) {
    super(contents, ProfileKey.checkLength(ProfileKey.SIZE));
  }

  getCommitment(userId: Aci): ProfileKeyCommitment {
    return new ProfileKeyCommitment(
      Native.ProfileKey_GetCommitment(
        this.contents,
        userId.getServiceIdFixedWidthBinary()
      )
    );
  }

  getProfileKeyVersion(userId: Aci): ProfileKeyVersion {
    return new ProfileKeyVersion(
      Native.ProfileKey_GetProfileKeyVersion(
        this.contents,
        userId.getServiceIdFixedWidthBinary()
      )
    );
  }

  deriveAccessKey(): Buffer {
    return Native.ProfileKey_DeriveAccessKey(this.contents);
  }
}

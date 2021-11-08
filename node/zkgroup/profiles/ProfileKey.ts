//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import ProfileKeyCommitment from './ProfileKeyCommitment';
import ProfileKeyVersion from './ProfileKeyVersion';
import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class ProfileKey extends ByteArray {
  static SIZE = 32;

  constructor(contents: Buffer) {
    super(contents, ProfileKey.checkLength(ProfileKey.SIZE));
  }

  getCommitment(uuid: UUIDType): ProfileKeyCommitment {
    return new ProfileKeyCommitment(
      NativeImpl.ProfileKey_GetCommitment(this.contents, fromUUID(uuid))
    );
  }

  getProfileKeyVersion(uuid: UUIDType): ProfileKeyVersion {
    return new ProfileKeyVersion(
      NativeImpl.ProfileKey_GetProfileKeyVersion(this.contents, fromUUID(uuid))
    );
  }
}

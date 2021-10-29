//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import { RANDOM_LENGTH } from '../internal/Constants';
import GroupMasterKey from './GroupMasterKey';
import GroupPublicParams from './GroupPublicParams';

export default class GroupSecretParams extends ByteArray {
  static SIZE = 289;

  static generate(): GroupSecretParams {
    const random = randomBytes(RANDOM_LENGTH);

    return GroupSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: Buffer): GroupSecretParams {
    return new GroupSecretParams(
      NativeImpl.GroupSecretParams_GenerateDeterministic(random)
    );
  }

  static deriveFromMasterKey(
    groupMasterKey: GroupMasterKey
  ): GroupSecretParams {
    return new GroupSecretParams(
      NativeImpl.GroupSecretParams_DeriveFromMasterKey(
        groupMasterKey.getContents()
      )
    );
  }

  constructor(contents: Buffer) {
    super(contents, GroupSecretParams.SIZE, true);
    NativeImpl.GroupSecretParams_CheckValidContents(this.contents);
  }

  getMasterKey(): GroupMasterKey {
    return new GroupMasterKey(
      NativeImpl.GroupSecretParams_GetMasterKey(this.contents)
    );
  }

  getPublicParams(): GroupPublicParams {
    return new GroupPublicParams(
      NativeImpl.GroupSecretParams_GetPublicParams(this.contents)
    );
  }
}

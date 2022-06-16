//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import { RANDOM_LENGTH } from '../internal/Constants';
import GroupMasterKey from './GroupMasterKey';
import GroupPublicParams from './GroupPublicParams';

export default class GroupSecretParams extends ByteArray {
  private readonly __type?: never;

  static generate(): GroupSecretParams {
    const random = randomBytes(RANDOM_LENGTH);

    return GroupSecretParams.generateWithRandom(random);
  }

  static generateWithRandom(random: Buffer): GroupSecretParams {
    return new GroupSecretParams(
      Native.GroupSecretParams_GenerateDeterministic(random)
    );
  }

  static deriveFromMasterKey(
    groupMasterKey: GroupMasterKey
  ): GroupSecretParams {
    return new GroupSecretParams(
      Native.GroupSecretParams_DeriveFromMasterKey(groupMasterKey.getContents())
    );
  }

  constructor(contents: Buffer) {
    super(contents, Native.GroupSecretParams_CheckValidContents);
  }

  getMasterKey(): GroupMasterKey {
    return new GroupMasterKey(
      Native.GroupSecretParams_GetMasterKey(this.contents)
    );
  }

  getPublicParams(): GroupPublicParams {
    return new GroupPublicParams(
      Native.GroupSecretParams_GetPublicParams(this.contents)
    );
  }
}

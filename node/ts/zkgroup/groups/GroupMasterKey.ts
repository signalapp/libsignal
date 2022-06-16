//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';

export default class GroupMasterKey extends ByteArray {
  private readonly __type?: never;
  static SIZE = 32;

  constructor(contents: Buffer) {
    super(contents, GroupMasterKey.checkLength(GroupMasterKey.SIZE));
  }
}

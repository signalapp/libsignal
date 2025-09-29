//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import { Buffer } from 'node:buffer';

export default class GroupIdentifier extends ByteArray {
  private readonly __type?: never;
  static SIZE = 32;

  constructor(contents: Uint8Array) {
    super(contents, GroupIdentifier.checkLength(GroupIdentifier.SIZE));
  }

  /** Returns the group ID as a base64 string (with padding). */
  toString(): string {
    return Buffer.from(this.contents).toString('base64');
  }
}

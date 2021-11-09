//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';

export default class ProfileKeyVersion extends ByteArray {
  static SIZE = 64;

  constructor(contents: Buffer | string) {
    super(
      typeof contents === 'string' ? Buffer.from(contents) : contents,
      ProfileKeyVersion.checkLength(ProfileKeyVersion.SIZE)
    );
  }

  toString(): string {
    return this.contents.toString('utf8');
  }
}

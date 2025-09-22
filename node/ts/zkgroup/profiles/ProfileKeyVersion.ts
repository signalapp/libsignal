//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';

export default class ProfileKeyVersion extends ByteArray {
  private readonly __type?: never;
  static SIZE = 64;

  constructor(contents: Uint8Array | string) {
    super(
      typeof contents === 'string'
        ? new TextEncoder().encode(contents)
        : contents,
      ProfileKeyVersion.checkLength(ProfileKeyVersion.SIZE)
    );
  }

  toString(): string {
    return new TextDecoder().decode(this.contents);
  }
}

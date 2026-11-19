//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

export default class ProfileKeyVersion {
  private readonly __type?: never;
  static SIZE = 64;
  private contents: Bytes;

  constructor(contents: Bytes | string) {
    this.contents =
      typeof contents === 'string'
        ? new TextEncoder().encode(contents)
        : contents;
    if (this.contents.length !== ProfileKeyVersion.SIZE) {
      throw new RangeError(
        `ProfileKeyVersion: expected ${ProfileKeyVersion.SIZE} bytes. Got ${this.contents.length}`
      );
    }
  }

  getContents(): Bytes {
    return new Uint8Array(this.contents);
  }

  toString(): string {
    return new TextDecoder().decode(this.contents);
  }
}

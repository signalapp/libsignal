//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { LibSignalErrorBase } from '../../Errors';

export default class ByteArray {
  contents: Buffer;

  constructor(contents: Buffer, checkValid: (contents: Buffer) => void) {
    checkValid(contents);
    this.contents = Buffer.from(contents);
  }

  protected static checkLength(
    expectedLength: number
  ): (contents: Buffer) => void {
    return (contents) => {
      if (contents.length !== expectedLength) {
        throw new LibSignalErrorBase(
          `Length of array supplied was ${contents.length} expected ${expectedLength}`,
          undefined,
          this.name
        );
      }
    };
  }

  public getContents(): Buffer {
    return this.contents;
  }

  public serialize(): Buffer {
    return Buffer.from(this.contents);
  }
}

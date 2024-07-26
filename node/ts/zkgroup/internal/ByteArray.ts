//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { LibSignalErrorBase } from '../../Errors';
import * as Native from '../../../Native';

export const UNCHECKED_AND_UNCLONED: unique symbol = Symbol();

export default class ByteArray {
  contents: Buffer;

  protected constructor(
    contents: Buffer,
    checkValid: ((contents: Buffer) => void) | typeof UNCHECKED_AND_UNCLONED
  ) {
    if (checkValid === UNCHECKED_AND_UNCLONED) {
      this.contents = contents;
    } else {
      checkValid.call(Native, contents);
      this.contents = Buffer.from(contents);
    }
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

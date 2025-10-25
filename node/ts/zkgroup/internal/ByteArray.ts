//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { LibSignalErrorBase } from '../../Errors.js';
import * as Native from '../../Native.js';

export const UNCHECKED_AND_UNCLONED: unique symbol = Symbol();

export default class ByteArray {
  contents: Uint8Array;

  protected constructor(
    contents: Uint8Array,
    checkValid: ((contents: Uint8Array) => void) | typeof UNCHECKED_AND_UNCLONED
  ) {
    if (checkValid === UNCHECKED_AND_UNCLONED) {
      this.contents = contents;
    } else {
      checkValid.call(Native, contents);
      this.contents = Uint8Array.from(contents);
    }
  }

  protected static checkLength(
    expectedLength: number
  ): (contents: Uint8Array) => void {
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

  public getContents(): Uint8Array {
    return this.contents;
  }

  public serialize(): Uint8Array {
    return Uint8Array.from(this.contents);
  }
}

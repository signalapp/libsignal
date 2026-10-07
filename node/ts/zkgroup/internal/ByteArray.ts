//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import { LibSignalErrorBase } from '../../Errors.js';
import * as Native from '../../Native.js';

export const UNCHECKED_AND_UNCLONED: unique symbol = Symbol();

export default class ByteArray {
  contents: Bytes;

  protected constructor(
    contents: Bytes,
    checkValid: ((contents: Bytes) => void) | typeof UNCHECKED_AND_UNCLONED
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
  ): (contents: Bytes) => void {
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

  public getContents(): Bytes {
    return this.contents;
  }

  public serialize(): Bytes {
    return Uint8Array.from(this.contents);
  }
}

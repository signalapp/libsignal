//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

export default class UuidCiphertext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.UuidCiphertext_CheckValidContents);
  }

  static serializeAndConcatenate(ciphertexts: UuidCiphertext[]): Buffer {
    if (ciphertexts.length == 0) {
      return Buffer.of();
    }

    const uuidCiphertextLen = ciphertexts[0].contents.length;
    const concatenated = Buffer.alloc(ciphertexts.length * uuidCiphertextLen);
    let offset = 0;
    for (const next of ciphertexts) {
      if (next.contents.length !== uuidCiphertextLen) {
        throw TypeError('UuidCiphertext with unexpected length');
      }
      concatenated.set(next.contents, offset);
      offset += uuidCiphertextLen;
    }

    return concatenated;
  }
}

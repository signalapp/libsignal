//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';

export default class ReceiptSerial extends ByteArray {
  private readonly __type?: never;
  static SIZE = 16;

  constructor(contents: Uint8Array) {
    super(contents, ReceiptSerial.checkLength(ReceiptSerial.SIZE));
  }
}

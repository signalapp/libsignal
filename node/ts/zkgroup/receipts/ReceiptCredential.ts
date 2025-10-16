//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

export default class ReceiptCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.ReceiptCredential_CheckValidContents);
  }

  getReceiptExpirationTime(): number {
    return Native.ReceiptCredential_GetReceiptExpirationTime(this.contents);
  }

  getReceiptLevel(): bigint {
    return Native.ReceiptCredential_GetReceiptLevel(this.contents);
  }
}

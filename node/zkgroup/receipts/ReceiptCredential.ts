//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ReceiptCredential extends ByteArray {
  constructor(contents: Buffer) {
    super(contents, NativeImpl.ReceiptCredential_CheckValidContents);
  }

  getReceiptExpirationTime(): bigint {
    return NativeImpl.ReceiptCredential_GetReceiptExpirationTime(
      this.contents
    ).readBigUInt64BE();
  }

  getReceiptLevel(): bigint {
    return NativeImpl.ReceiptCredential_GetReceiptLevel(
      this.contents
    ).readBigUInt64BE();
  }
}

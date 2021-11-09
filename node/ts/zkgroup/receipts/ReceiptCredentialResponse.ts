//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

export default class ReceiptCredentialResponse extends ByteArray {
  constructor(contents: Buffer) {
    super(contents, Native.ReceiptCredentialResponse_CheckValidContents);
  }
}

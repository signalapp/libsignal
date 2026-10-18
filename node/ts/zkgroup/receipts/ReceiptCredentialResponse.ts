//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

export default class ReceiptCredentialResponse extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Bytes) {
    super(contents, Native.ReceiptCredentialResponse_CheckValidContents);
  }
}

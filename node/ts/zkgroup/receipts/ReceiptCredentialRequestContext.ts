//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';
import ReceiptCredentialRequest from './ReceiptCredentialRequest.js';

export default class ReceiptCredentialRequestContext extends ByteArray {
  private readonly __type?: never;
  static SIZE = 177;

  constructor(contents: Bytes) {
    super(contents, Native.ReceiptCredentialRequestContext_CheckValidContents);
  }

  getRequest(): ReceiptCredentialRequest {
    return new ReceiptCredentialRequest(
      Native.ReceiptCredentialRequestContext_GetRequest(this.contents)
    );
  }
}

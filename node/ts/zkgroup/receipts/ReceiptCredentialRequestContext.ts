//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import ReceiptCredentialRequest from './ReceiptCredentialRequest';

export default class ReceiptCredentialRequestContext extends ByteArray {
  private readonly __type?: never;
  static SIZE = 177;

  constructor(contents: Buffer) {
    super(contents, Native.ReceiptCredentialRequestContext_CheckValidContents);
  }

  getRequest(): ReceiptCredentialRequest {
    return new ReceiptCredentialRequest(
      Native.ReceiptCredentialRequestContext_GetRequest(this.contents)
    );
  }
}

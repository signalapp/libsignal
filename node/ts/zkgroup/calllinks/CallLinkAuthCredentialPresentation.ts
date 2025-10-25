//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

import CallLinkPublicParams from './CallLinkPublicParams.js';
import GenericServerSecretParams from '../GenericServerSecretParams.js';
import UuidCiphertext from '../groups/UuidCiphertext.js';

export default class CallLinkAuthCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(
      contents,
      Native.CallLinkAuthCredentialPresentation_CheckValidContents
    );
  }

  verify(
    serverParams: GenericServerSecretParams,
    callLinkParams: CallLinkPublicParams,
    now: Date = new Date()
  ): void {
    Native.CallLinkAuthCredentialPresentation_Verify(
      this.contents,
      Math.floor(now.getTime() / 1000),
      serverParams.contents,
      callLinkParams.contents
    );
  }

  getUserId(): UuidCiphertext {
    return new UuidCiphertext(
      Native.CallLinkAuthCredentialPresentation_GetUserId(this.contents)
    );
  }
}

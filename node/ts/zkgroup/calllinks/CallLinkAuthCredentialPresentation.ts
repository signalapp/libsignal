//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

import CallLinkPublicParams from './CallLinkPublicParams';
import GenericServerSecretParams from '../GenericServerSecretParams';
import UuidCiphertext from '../groups/UuidCiphertext';

export default class CallLinkAuthCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
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

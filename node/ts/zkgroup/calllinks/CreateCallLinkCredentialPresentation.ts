//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

import CallLinkPublicParams from './CallLinkPublicParams.js';
import GenericServerSecretParams from '../GenericServerSecretParams.js';

export default class CreateCallLinkCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(
      contents,
      Native.CreateCallLinkCredentialPresentation_CheckValidContents
    );
  }

  verify(
    roomId: Uint8Array,
    serverParams: GenericServerSecretParams,
    callLinkParams: CallLinkPublicParams,
    now: Date = new Date()
  ): void {
    Native.CreateCallLinkCredentialPresentation_Verify(
      this.contents,
      roomId,
      Math.floor(now.getTime() / 1000),
      serverParams.contents,
      callLinkParams.contents
    );
  }
}

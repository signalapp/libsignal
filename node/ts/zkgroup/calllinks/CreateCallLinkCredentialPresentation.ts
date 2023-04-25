//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

import CallLinkPublicParams from './CallLinkPublicParams';
import GenericServerSecretParams from '../GenericServerSecretParams';

export default class CreateCallLinkCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(
      contents,
      Native.CreateCallLinkCredentialPresentation_CheckValidContents
    );
  }

  verify(
    roomId: Buffer,
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

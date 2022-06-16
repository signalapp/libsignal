//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from './internal/ByteArray';
import * as Native from '../../Native';
import NotarySignature from './NotarySignature';

export default class ServerPublicParams extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.ServerPublicParams_CheckValidContents);
  }

  verifySignature(message: Buffer, notarySignature: NotarySignature): void {
    Native.ServerPublicParams_VerifySignature(
      this.contents,
      message,
      notarySignature.getContents()
    );
  }
}

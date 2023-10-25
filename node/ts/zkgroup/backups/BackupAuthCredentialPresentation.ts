//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

import GenericServerSecretParams from '../GenericServerSecretParams';

export default class BackupAuthCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.BackupAuthCredentialPresentation_CheckValidContents);
  }

  verify(
    serverParams: GenericServerSecretParams,
    now: Date = new Date()
  ): void {
    Native.BackupAuthCredentialPresentation_Verify(
      this.contents,
      Math.floor(now.getTime() / 1000),
      serverParams.contents
    );
  }
}

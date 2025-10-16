//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

import GenericServerSecretParams from '../GenericServerSecretParams.js';
import BackupLevel from './BackupLevel.js';
import BackupCredentialType from './BackupCredentialType.js';

export default class BackupAuthCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
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

  getBackupId(): Uint8Array {
    return Native.BackupAuthCredentialPresentation_GetBackupId(this.contents);
  }

  getBackupLevel(): BackupLevel {
    const n: number = Native.BackupAuthCredentialPresentation_GetBackupLevel(
      this.contents
    );
    if (!(n in BackupLevel)) {
      throw new TypeError(`Invalid BackupLevel ${n}`);
    }
    return n;
  }

  getType(): BackupCredentialType {
    const n: number = Native.BackupAuthCredentialPresentation_GetType(
      this.contents
    );
    if (!(n in BackupCredentialType)) {
      throw new TypeError(`Invalid BackupCredentialType ${n}`);
    }
    return n;
  }
}

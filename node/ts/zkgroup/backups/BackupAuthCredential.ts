//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import * as Native from '../../Native.js';
import ByteArray from '../internal/ByteArray.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';

import GenericServerPublicParams from '../GenericServerPublicParams.js';
import BackupAuthCredentialPresentation from './BackupAuthCredentialPresentation.js';
import BackupLevel from './BackupLevel.js';
import BackupCredentialType from './BackupCredentialType.js';

export default class BackupAuthCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.BackupAuthCredential_CheckValidContents);
  }

  present(
    serverParams: GenericServerPublicParams
  ): BackupAuthCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);
    return this.presentWithRandom(serverParams, random);
  }

  presentWithRandom(
    serverParams: GenericServerPublicParams,
    random: Uint8Array
  ): BackupAuthCredentialPresentation {
    return new BackupAuthCredentialPresentation(
      Native.BackupAuthCredential_PresentDeterministic(
        this.contents,
        serverParams.contents,
        random
      )
    );
  }

  getBackupId(): Uint8Array {
    return Native.BackupAuthCredential_GetBackupId(this.contents);
  }

  getBackupLevel(): BackupLevel {
    const n: number = Native.BackupAuthCredential_GetBackupLevel(this.contents);
    if (!(n in BackupLevel)) {
      throw new TypeError(`Invalid BackupLevel ${n}`);
    }
    return n;
  }

  getType(): BackupCredentialType {
    const n: number = Native.BackupAuthCredential_GetType(this.contents);
    if (!(n in BackupCredentialType)) {
      throw new TypeError(`Invalid BackupCredentialType ${n}`);
    }
    return n;
  }
}

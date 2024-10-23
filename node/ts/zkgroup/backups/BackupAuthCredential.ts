//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import * as Native from '../../../Native';
import ByteArray from '../internal/ByteArray';
import { RANDOM_LENGTH } from '../internal/Constants';

import GenericServerPublicParams from '../GenericServerPublicParams';
import BackupAuthCredentialPresentation from './BackupAuthCredentialPresentation';
import BackupLevel from './BackupLevel';
import BackupCredentialType from './BackupCredentialType';

export default class BackupAuthCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
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
    random: Buffer
  ): BackupAuthCredentialPresentation {
    return new BackupAuthCredentialPresentation(
      Native.BackupAuthCredential_PresentDeterministic(
        this.contents,
        serverParams.contents,
        random
      )
    );
  }

  getBackupId(): Buffer {
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

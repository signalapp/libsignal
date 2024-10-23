//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import * as Native from '../../../Native';
import ByteArray from '../internal/ByteArray';
import { RANDOM_LENGTH } from '../internal/Constants';

import GenericServerSecretParams from '../GenericServerSecretParams';
import BackupAuthCredentialResponse from './BackupAuthCredentialResponse';
import BackupLevel from './BackupLevel';
import BackupCredentialType from './BackupCredentialType';

export default class BackupAuthCredentialRequest extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.BackupAuthCredentialRequest_CheckValidContents);
  }

  issueCredential(
    timestamp: number,
    backupLevel: BackupLevel,
    type: BackupCredentialType,
    params: GenericServerSecretParams
  ): BackupAuthCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueCredentialWithRandom(
      timestamp,
      backupLevel,
      type,
      params,
      random
    );
  }

  issueCredentialWithRandom(
    timestamp: number,
    backupLevel: BackupLevel,
    type: BackupCredentialType,
    params: GenericServerSecretParams,
    random: Buffer
  ): BackupAuthCredentialResponse {
    return new BackupAuthCredentialResponse(
      Native.BackupAuthCredentialRequest_IssueDeterministic(
        this.contents,
        timestamp,
        backupLevel,
        type,
        params.contents,
        random
      )
    );
  }
}

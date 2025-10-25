//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import * as Native from '../../Native.js';
import ByteArray from '../internal/ByteArray.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';

import GenericServerSecretParams from '../GenericServerSecretParams.js';
import BackupAuthCredentialResponse from './BackupAuthCredentialResponse.js';
import BackupLevel from './BackupLevel.js';
import BackupCredentialType from './BackupCredentialType.js';

export default class BackupAuthCredentialRequest extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
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
    random: Uint8Array
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

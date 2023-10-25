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
import { bufferFromBigUInt64BE } from '../internal/BigIntUtil';

export default class BackupAuthCredentialRequest extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.BackupAuthCredentialRequest_CheckValidContents);
  }

  issueCredential(
    timestamp: number,
    receiptLevel: bigint,
    params: GenericServerSecretParams
  ): BackupAuthCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueCredentialWithRandom(
      timestamp,
      receiptLevel,
      params,
      random
    );
  }

  issueCredentialWithRandom(
    timestamp: number,
    receiptLevel: bigint,
    params: GenericServerSecretParams,
    random: Buffer
  ): BackupAuthCredentialResponse {
    return new BackupAuthCredentialResponse(
      Native.BackupAuthCredentialRequest_IssueDeterministic(
        this.contents,
        timestamp,
        bufferFromBigUInt64BE(receiptLevel),
        params.contents,
        random
      )
    );
  }
}

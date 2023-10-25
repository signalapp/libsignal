//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as uuid from 'uuid';

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

import BackupAuthCredentialRequest from './BackupAuthCredentialRequest';
import BackupAuthCredentialResponse from './BackupAuthCredentialResponse';
import BackupAuthCredential from './BackupAuthCredential';
import GenericServerPublicParams from '../GenericServerPublicParams';
import { bufferFromBigUInt64BE } from '../internal/BigIntUtil';
import { Uuid } from '../..';

export default class BackupAuthCredentialRequestContext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(
      contents,
      Native.BackupAuthCredentialRequestContext_CheckValidContents
    );
  }

  static create(
    backupKey: Buffer,
    aci: Uuid
  ): BackupAuthCredentialRequestContext {
    return new BackupAuthCredentialRequestContext(
      Native.BackupAuthCredentialRequestContext_New(
        backupKey,
        Buffer.from(uuid.parse(aci) as Uint8Array)
      )
    );
  }

  getRequest(): BackupAuthCredentialRequest {
    return new BackupAuthCredentialRequest(
      Native.BackupAuthCredentialRequestContext_GetRequest(this.contents)
    );
  }

  receive(
    response: BackupAuthCredentialResponse,
    params: GenericServerPublicParams,
    expectedReceiptLevel: bigint
  ): BackupAuthCredential {
    return new BackupAuthCredential(
      Native.BackupAuthCredentialRequestContext_ReceiveResponse(
        this.contents,
        response.contents,
        params.contents,
        bufferFromBigUInt64BE(expectedReceiptLevel)
      )
    );
  }
}

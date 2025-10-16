//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as uuid from 'uuid';

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

import BackupAuthCredentialRequest from './BackupAuthCredentialRequest.js';
import BackupAuthCredentialResponse from './BackupAuthCredentialResponse.js';
import BackupAuthCredential from './BackupAuthCredential.js';
import GenericServerPublicParams from '../GenericServerPublicParams.js';
import type { Uuid } from '../../index.js';

export default class BackupAuthCredentialRequestContext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(
      contents,
      Native.BackupAuthCredentialRequestContext_CheckValidContents
    );
  }

  static create(
    backupKey: Uint8Array,
    aci: Uuid
  ): BackupAuthCredentialRequestContext {
    return new BackupAuthCredentialRequestContext(
      Native.BackupAuthCredentialRequestContext_New(backupKey, uuid.parse(aci))
    );
  }

  getRequest(): BackupAuthCredentialRequest {
    return new BackupAuthCredentialRequest(
      Native.BackupAuthCredentialRequestContext_GetRequest(this.contents)
    );
  }

  receive(
    response: BackupAuthCredentialResponse,
    redemptionTime: number,
    params: GenericServerPublicParams
  ): BackupAuthCredential {
    return new BackupAuthCredential(
      Native.BackupAuthCredentialRequestContext_ReceiveResponse(
        this.contents,
        response.contents,
        redemptionTime,
        params.contents
      )
    );
  }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import ByteArray from '../internal/ByteArray.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';
import * as Native from '../../Native.js';

import CreateCallLinkCredentialResponse from './CreateCallLinkCredentialResponse.js';
import GenericServerSecretParams from '../GenericServerSecretParams.js';
import { Aci } from '../../Address.js';

export default class CreateCallLinkCredentialRequest extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.CreateCallLinkCredentialRequest_CheckValidContents);
  }

  issueCredential(
    userId: Aci,
    timestamp: number,
    params: GenericServerSecretParams
  ): CreateCallLinkCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueCredentialWithRandom(userId, timestamp, params, random);
  }

  issueCredentialWithRandom(
    userId: Aci,
    timestamp: number,
    params: GenericServerSecretParams,
    random: Uint8Array
  ): CreateCallLinkCredentialResponse {
    return new CreateCallLinkCredentialResponse(
      Native.CreateCallLinkCredentialRequest_IssueDeterministic(
        this.contents,
        userId.getServiceIdFixedWidthBinary(),
        timestamp,
        params.contents,
        random
      )
    );
  }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import CreateCallLinkCredentialResponse from './CreateCallLinkCredentialResponse';
import GenericServerSecretParams from '../GenericServerSecretParams';
import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class CreateCallLinkCredentialRequest extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.CreateCallLinkCredentialRequest_CheckValidContents);
  }

  issueCredential(
    userId: UUIDType,
    timestamp: number,
    params: GenericServerSecretParams
  ): CreateCallLinkCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueCredentialWithRandom(userId, timestamp, params, random);
  }

  issueCredentialWithRandom(
    userId: UUIDType,
    timestamp: number,
    params: GenericServerSecretParams,
    random: Buffer
  ): CreateCallLinkCredentialResponse {
    return new CreateCallLinkCredentialResponse(
      Native.CreateCallLinkCredentialRequest_IssueDeterministic(
        this.contents,
        fromUUID(userId),
        timestamp,
        params.contents,
        random
      )
    );
  }
}

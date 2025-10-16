//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';

import GenericServerSecretParams from '../GenericServerSecretParams.js';
import GenericServerPublicParams from '../GenericServerPublicParams.js';
import CallLinkAuthCredential from './CallLinkAuthCredential.js';
import { Aci } from '../../Address.js';

export default class CallLinkAuthCredentialResponse extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.CallLinkAuthCredentialResponse_CheckValidContents);
  }

  static issueCredential(
    userId: Aci,
    redemptionTime: number,
    params: GenericServerSecretParams
  ): CallLinkAuthCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueCredentialWithRandom(
      userId,
      redemptionTime,
      params,
      random
    );
  }

  static issueCredentialWithRandom(
    userId: Aci,
    redemptionTime: number,
    params: GenericServerSecretParams,
    random: Uint8Array
  ): CallLinkAuthCredentialResponse {
    return new CallLinkAuthCredentialResponse(
      Native.CallLinkAuthCredentialResponse_IssueDeterministic(
        userId.getServiceIdFixedWidthBinary(),
        redemptionTime,
        params.contents,
        random
      )
    );
  }

  receive(
    userId: Aci,
    redemptionTime: number,
    params: GenericServerPublicParams
  ): CallLinkAuthCredential {
    return new CallLinkAuthCredential(
      Native.CallLinkAuthCredentialResponse_Receive(
        this.contents,
        userId.getServiceIdFixedWidthBinary(),
        redemptionTime,
        params.contents
      )
    );
  }
}

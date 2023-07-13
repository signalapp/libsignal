//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import GenericServerSecretParams from '../GenericServerSecretParams';
import GenericServerPublicParams from '../GenericServerPublicParams';
import CallLinkAuthCredential from './CallLinkAuthCredential';
import { Aci } from '../../Address';

export default class CallLinkAuthCredentialResponse extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
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
    random: Buffer
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

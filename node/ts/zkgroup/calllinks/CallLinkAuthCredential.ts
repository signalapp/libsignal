//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import ByteArray from '../internal/ByteArray.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';
import * as Native from '../../Native.js';

import CallLinkSecretParams from './CallLinkSecretParams.js';
import CallLinkAuthCredentialPresentation from './CallLinkAuthCredentialPresentation.js';
import GenericServerPublicParams from '../GenericServerPublicParams.js';
import { Aci } from '../../Address.js';

export default class CallLinkAuthCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.CallLinkAuthCredential_CheckValidContents);
  }

  present(
    userId: Aci,
    redemptionTime: number,
    serverParams: GenericServerPublicParams,
    callLinkParams: CallLinkSecretParams
  ): CallLinkAuthCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);
    return this.presentWithRandom(
      userId,
      redemptionTime,
      serverParams,
      callLinkParams,
      random
    );
  }

  presentWithRandom(
    userId: Aci,
    redemptionTime: number,
    serverParams: GenericServerPublicParams,
    callLinkParams: CallLinkSecretParams,
    random: Uint8Array
  ): CallLinkAuthCredentialPresentation {
    return new CallLinkAuthCredentialPresentation(
      Native.CallLinkAuthCredential_PresentDeterministic(
        this.contents,
        userId.getServiceIdFixedWidthBinary(),
        redemptionTime,
        serverParams.contents,
        callLinkParams.contents,
        random
      )
    );
  }
}

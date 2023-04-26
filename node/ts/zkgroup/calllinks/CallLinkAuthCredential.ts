//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import CallLinkSecretParams from './CallLinkSecretParams';
import CallLinkAuthCredentialPresentation from './CallLinkAuthCredentialPresentation';
import GenericServerPublicParams from '../GenericServerPublicParams';
import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class CallLinkAuthCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.CallLinkAuthCredential_CheckValidContents);
  }

  present(
    userId: UUIDType,
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
    userId: UUIDType,
    redemptionTime: number,
    serverParams: GenericServerPublicParams,
    callLinkParams: CallLinkSecretParams,
    random: Buffer
  ): CallLinkAuthCredentialPresentation {
    return new CallLinkAuthCredentialPresentation(
      Native.CallLinkAuthCredential_PresentDeterministic(
        this.contents,
        fromUUID(userId),
        redemptionTime,
        serverParams.contents,
        callLinkParams.contents,
        random
      )
    );
  }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import CallLinkSecretParams from './CallLinkSecretParams';
import CreateCallLinkCredentialPresentation from './CreateCallLinkCredentialPresentation';
import GenericServerPublicParams from '../GenericServerPublicParams';
import { Aci } from '../../Address';

export default class CreateCallLinkCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.CreateCallLinkCredential_CheckValidContents);
  }

  present(
    roomId: Buffer,
    userId: Aci,
    serverParams: GenericServerPublicParams,
    callLinkParams: CallLinkSecretParams
  ): CreateCallLinkCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);
    return this.presentWithRandom(
      roomId,
      userId,
      serverParams,
      callLinkParams,
      random
    );
  }

  presentWithRandom(
    roomId: Buffer,
    userId: Aci,
    serverParams: GenericServerPublicParams,
    callLinkParams: CallLinkSecretParams,
    random: Buffer
  ): CreateCallLinkCredentialPresentation {
    return new CreateCallLinkCredentialPresentation(
      Native.CreateCallLinkCredential_PresentDeterministic(
        this.contents,
        roomId,
        userId.getServiceIdFixedWidthBinary(),
        serverParams.contents,
        callLinkParams.contents,
        random
      )
    );
  }
}

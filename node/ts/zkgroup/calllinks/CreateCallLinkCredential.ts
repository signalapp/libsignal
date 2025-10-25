//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import ByteArray from '../internal/ByteArray.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';
import * as Native from '../../Native.js';

import CallLinkSecretParams from './CallLinkSecretParams.js';
import CreateCallLinkCredentialPresentation from './CreateCallLinkCredentialPresentation.js';
import GenericServerPublicParams from '../GenericServerPublicParams.js';
import { Aci } from '../../Address.js';

export default class CreateCallLinkCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.CreateCallLinkCredential_CheckValidContents);
  }

  present(
    roomId: Uint8Array,
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
    roomId: Uint8Array,
    userId: Aci,
    serverParams: GenericServerPublicParams,
    callLinkParams: CallLinkSecretParams,
    random: Uint8Array
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

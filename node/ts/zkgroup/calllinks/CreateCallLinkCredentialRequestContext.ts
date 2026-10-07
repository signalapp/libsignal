//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';
import { randomBytes } from 'node:crypto';

import ByteArray from '../internal/ByteArray.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';
import * as Native from '../../Native.js';

import CreateCallLinkCredentialRequest from './CreateCallLinkCredentialRequest.js';
import CreateCallLinkCredentialResponse from './CreateCallLinkCredentialResponse.js';
import CreateCallLinkCredential from './CreateCallLinkCredential.js';
import GenericServerPublicParams from '../GenericServerPublicParams.js';
import { Aci } from '../../Address.js';

export default class CreateCallLinkCredentialRequestContext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Bytes) {
    super(
      contents,
      Native.CreateCallLinkCredentialRequestContext_CheckValidContents
    );
  }

  static forRoomId(roomId: Bytes): CreateCallLinkCredentialRequestContext {
    const random = randomBytes(RANDOM_LENGTH);
    return this.forRoomIdWithRandom(roomId, random);
  }

  static forRoomIdWithRandom(
    roomId: Bytes,
    random: Bytes
  ): CreateCallLinkCredentialRequestContext {
    return new CreateCallLinkCredentialRequestContext(
      Native.CreateCallLinkCredentialRequestContext_NewDeterministic(
        roomId,
        random
      )
    );
  }

  getRequest(): CreateCallLinkCredentialRequest {
    return new CreateCallLinkCredentialRequest(
      Native.CreateCallLinkCredentialRequestContext_GetRequest(this.contents)
    );
  }

  receive(
    response: CreateCallLinkCredentialResponse,
    userId: Aci,
    params: GenericServerPublicParams
  ): CreateCallLinkCredential {
    return new CreateCallLinkCredential(
      Native.CreateCallLinkCredentialRequestContext_ReceiveResponse(
        this.contents,
        response.contents,
        userId.getServiceIdFixedWidthBinary(),
        params.contents
      )
    );
  }
}

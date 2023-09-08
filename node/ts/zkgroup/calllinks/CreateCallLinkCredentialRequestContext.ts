//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import CreateCallLinkCredentialRequest from './CreateCallLinkCredentialRequest';
import CreateCallLinkCredentialResponse from './CreateCallLinkCredentialResponse';
import CreateCallLinkCredential from './CreateCallLinkCredential';
import GenericServerPublicParams from '../GenericServerPublicParams';
import { Aci } from '../../Address';

export default class CreateCallLinkCredentialRequestContext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(
      contents,
      Native.CreateCallLinkCredentialRequestContext_CheckValidContents
    );
  }

  static forRoomId(roomId: Buffer): CreateCallLinkCredentialRequestContext {
    const random = randomBytes(RANDOM_LENGTH);
    return this.forRoomIdWithRandom(roomId, random);
  }

  static forRoomIdWithRandom(
    roomId: Buffer,
    random: Buffer
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

//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import { RANDOM_LENGTH } from '../internal/Constants.js';
import * as Native from '../../Native.js';

import ServerPublicParams from '../ServerPublicParams.js';
import GroupSecretParams from '../groups/GroupSecretParams.js';

import ExpiringProfileKeyCredential from './ExpiringProfileKeyCredential.js';
import ExpiringProfileKeyCredentialResponse from './ExpiringProfileKeyCredentialResponse.js';
import ProfileKey from './ProfileKey.js';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation.js';
import ProfileKeyCredentialRequestContext from './ProfileKeyCredentialRequestContext.js';

import { Aci } from '../../Address.js';

export default class ClientZkProfileOperations {
  serverPublicParams: ServerPublicParams;

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  createProfileKeyCredentialRequestContext(
    userId: Aci,
    profileKey: ProfileKey
  ): ProfileKeyCredentialRequestContext {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createProfileKeyCredentialRequestContextWithRandom(
      random,
      userId,
      profileKey
    );
  }

  createProfileKeyCredentialRequestContextWithRandom(
    random: Uint8Array,
    userId: Aci,
    profileKey: ProfileKey
  ): ProfileKeyCredentialRequestContext {
    return new ProfileKeyCredentialRequestContext(
      Native.ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(
        this.serverPublicParams,
        random,
        userId.getServiceIdFixedWidthBinary(),
        profileKey.getContents()
      )
    );
  }

  receiveExpiringProfileKeyCredential(
    profileKeyCredentialRequestContext: ProfileKeyCredentialRequestContext,
    profileKeyCredentialResponse: ExpiringProfileKeyCredentialResponse,
    now: Date = new Date()
  ): ExpiringProfileKeyCredential {
    return new ExpiringProfileKeyCredential(
      Native.ServerPublicParams_ReceiveExpiringProfileKeyCredential(
        this.serverPublicParams,
        profileKeyCredentialRequestContext.getContents(),
        profileKeyCredentialResponse.getContents(),
        Math.floor(now.getTime() / 1000)
      )
    );
  }

  createExpiringProfileKeyCredentialPresentation(
    groupSecretParams: GroupSecretParams,
    profileKeyCredential: ExpiringProfileKeyCredential
  ): ProfileKeyCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createExpiringProfileKeyCredentialPresentationWithRandom(
      random,
      groupSecretParams,
      profileKeyCredential
    );
  }

  createExpiringProfileKeyCredentialPresentationWithRandom(
    random: Uint8Array,
    groupSecretParams: GroupSecretParams,
    profileKeyCredential: ExpiringProfileKeyCredential
  ): ProfileKeyCredentialPresentation {
    return new ProfileKeyCredentialPresentation(
      Native.ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(
        this.serverPublicParams,
        random,
        groupSecretParams.getContents(),
        profileKeyCredential.getContents()
      )
    );
  }
}

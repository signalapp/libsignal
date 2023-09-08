//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import ServerPublicParams from '../ServerPublicParams';
import GroupSecretParams from '../groups/GroupSecretParams';

import ExpiringProfileKeyCredential from './ExpiringProfileKeyCredential';
import ExpiringProfileKeyCredentialResponse from './ExpiringProfileKeyCredentialResponse';
import ProfileKey from './ProfileKey';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';
import ProfileKeyCredentialRequestContext from './ProfileKeyCredentialRequestContext';

import { Aci } from '../../Address';

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
    random: Buffer,
    userId: Aci,
    profileKey: ProfileKey
  ): ProfileKeyCredentialRequestContext {
    return new ProfileKeyCredentialRequestContext(
      Native.ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(
        this.serverPublicParams.getContents(),
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
        this.serverPublicParams.getContents(),
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
    random: Buffer,
    groupSecretParams: GroupSecretParams,
    profileKeyCredential: ExpiringProfileKeyCredential
  ): ProfileKeyCredentialPresentation {
    return new ProfileKeyCredentialPresentation(
      Native.ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(
        this.serverPublicParams.getContents(),
        random,
        groupSecretParams.getContents(),
        profileKeyCredential.getContents()
      )
    );
  }
}

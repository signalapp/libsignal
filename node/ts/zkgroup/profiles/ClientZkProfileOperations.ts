//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import ServerPublicParams from '../ServerPublicParams';
import ProfileKeyCredentialRequestContext from './ProfileKeyCredentialRequestContext';
import ProfileKey from './ProfileKey';
import ProfileKeyCredential from './ProfileKeyCredential';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';
import GroupSecretParams from '../groups/GroupSecretParams';
import ProfileKeyCredentialResponse from './ProfileKeyCredentialResponse';

import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class ClientZkProfileOperations {
  serverPublicParams: ServerPublicParams;

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  createProfileKeyCredentialRequestContext(
    uuid: UUIDType,
    profileKey: ProfileKey
  ): ProfileKeyCredentialRequestContext {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createProfileKeyCredentialRequestContextWithRandom(
      random,
      uuid,
      profileKey
    );
  }

  createProfileKeyCredentialRequestContextWithRandom(
    random: Buffer,
    uuid: UUIDType,
    profileKey: ProfileKey
  ): ProfileKeyCredentialRequestContext {
    return new ProfileKeyCredentialRequestContext(
      Native.ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(
        this.serverPublicParams.getContents(),
        random,
        fromUUID(uuid),
        profileKey.getContents()
      )
    );
  }

  receiveProfileKeyCredential(
    profileKeyCredentialRequestContext: ProfileKeyCredentialRequestContext,
    profileKeyCredentialResponse: ProfileKeyCredentialResponse
  ): ProfileKeyCredential {
    return new ProfileKeyCredential(
      Native.ServerPublicParams_ReceiveProfileKeyCredential(
        this.serverPublicParams.getContents(),
        profileKeyCredentialRequestContext.getContents(),
        profileKeyCredentialResponse.getContents()
      )
    );
  }

  createProfileKeyCredentialPresentation(
    groupSecretParams: GroupSecretParams,
    profileKeyCredential: ProfileKeyCredential
  ): ProfileKeyCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createProfileKeyCredentialPresentationWithRandom(
      random,
      groupSecretParams,
      profileKeyCredential
    );
  }

  createProfileKeyCredentialPresentationWithRandom(
    random: Buffer,
    groupSecretParams: GroupSecretParams,
    profileKeyCredential: ProfileKeyCredential
  ): ProfileKeyCredentialPresentation {
    return new ProfileKeyCredentialPresentation(
      Native.ServerPublicParams_CreateProfileKeyCredentialPresentationDeterministic(
        this.serverPublicParams.getContents(),
        random,
        groupSecretParams.getContents(),
        profileKeyCredential.getContents()
      )
    );
  }
}

//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import ServerPublicParams from '../ServerPublicParams';
import GroupSecretParams from '../groups/GroupSecretParams';

import PniCredential from './PniCredential';
import PniCredentialPresentation from './PniCredentialPresentation';
import PniCredentialRequestContext from './PniCredentialRequestContext';
import PniCredentialResponse from './PniCredentialResponse';
import ProfileKey from './ProfileKey';
import ProfileKeyCredential from './ProfileKeyCredential';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';
import ProfileKeyCredentialRequestContext from './ProfileKeyCredentialRequestContext';
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

  createPniCredentialRequestContext(
    aci: UUIDType,
    pni: UUIDType,
    profileKey: ProfileKey
  ): PniCredentialRequestContext {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createPniCredentialRequestContextWithRandom(
      random,
      aci,
      pni,
      profileKey
    );
  }

  createPniCredentialRequestContextWithRandom(
    random: Buffer,
    aci: UUIDType,
    pni: UUIDType,
    profileKey: ProfileKey
  ): PniCredentialRequestContext {
    return new PniCredentialRequestContext(
      Native.ServerPublicParams_CreatePniCredentialRequestContextDeterministic(
        this.serverPublicParams.getContents(),
        random,
        fromUUID(aci),
        fromUUID(pni),
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

  receivePniCredential(
    requestContext: PniCredentialRequestContext,
    response: PniCredentialResponse
  ): PniCredential {
    return new PniCredential(
      Native.ServerPublicParams_ReceivePniCredential(
        this.serverPublicParams.getContents(),
        requestContext.getContents(),
        response.getContents()
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

  createPniCredentialPresentation(
    groupSecretParams: GroupSecretParams,
    credential: PniCredential
  ): PniCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createPniCredentialPresentationWithRandom(
      random,
      groupSecretParams,
      credential
    );
  }

  createPniCredentialPresentationWithRandom(
    random: Buffer,
    groupSecretParams: GroupSecretParams,
    credential: PniCredential
  ): PniCredentialPresentation {
    return new PniCredentialPresentation(
      Native.ServerPublicParams_CreatePniCredentialPresentationDeterministic(
        this.serverPublicParams.getContents(),
        random,
        groupSecretParams.getContents(),
        credential.getContents()
      )
    );
  }
}

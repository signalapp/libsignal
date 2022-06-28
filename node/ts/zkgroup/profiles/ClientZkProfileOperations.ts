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

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential
   */
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

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential
   */
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

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential
   */
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

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential
   */
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

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential
   */
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

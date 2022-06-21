//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import * as Native from '../../../Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import ServerPublicParams from '../ServerPublicParams';
import AuthCredential from './AuthCredential';
import AuthCredentialPresentation from './AuthCredentialPresentation';
import AuthCredentialResponse from './AuthCredentialResponse';
import AuthCredentialWithPni from './AuthCredentialWithPni';
import AuthCredentialWithPniResponse from './AuthCredentialWithPniResponse';
import GroupSecretParams from '../groups/GroupSecretParams';
import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class ClientZkAuthOperations {
  serverPublicParams: ServerPublicParams;

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  receiveAuthCredential(
    uuid: UUIDType,
    redemptionTime: number,
    authCredentialResponse: AuthCredentialResponse
  ): AuthCredential {
    return new AuthCredential(
      Native.ServerPublicParams_ReceiveAuthCredential(
        this.serverPublicParams.getContents(),
        fromUUID(uuid),
        redemptionTime,
        authCredentialResponse.getContents()
      )
    );
  }

  /**
   * Produces the AuthCredentialWithPni from a server-generated AuthCredentialWithPniResponse.
   *
   * @param redemptionTime - This is provided by the server as an integer, and should be passed through directly.
   */
  receiveAuthCredentialWithPni(
    aci: UUIDType,
    pni: UUIDType,
    redemptionTime: number,
    authCredentialResponse: AuthCredentialWithPniResponse
  ): AuthCredentialWithPni {
    return new AuthCredentialWithPni(
      Native.ServerPublicParams_ReceiveAuthCredentialWithPni(
        this.serverPublicParams.getContents(),
        fromUUID(aci),
        fromUUID(pni),
        redemptionTime,
        authCredentialResponse.getContents()
      )
    );
  }

  createAuthCredentialPresentation(
    groupSecretParams: GroupSecretParams,
    authCredential: AuthCredential
  ): AuthCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createAuthCredentialPresentationWithRandom(
      random,
      groupSecretParams,
      authCredential
    );
  }

  createAuthCredentialPresentationWithRandom(
    random: Buffer,
    groupSecretParams: GroupSecretParams,
    authCredential: AuthCredential
  ): AuthCredentialPresentation {
    return new AuthCredentialPresentation(
      Native.ServerPublicParams_CreateAuthCredentialPresentationDeterministic(
        this.serverPublicParams.getContents(),
        random,
        groupSecretParams.getContents(),
        authCredential.getContents()
      )
    );
  }

  createAuthCredentialWithPniPresentation(
    groupSecretParams: GroupSecretParams,
    authCredential: AuthCredentialWithPni
  ): AuthCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);

    return this.createAuthCredentialWithPniPresentationWithRandom(
      random,
      groupSecretParams,
      authCredential
    );
  }

  createAuthCredentialWithPniPresentationWithRandom(
    random: Buffer,
    groupSecretParams: GroupSecretParams,
    authCredential: AuthCredentialWithPni
  ): AuthCredentialPresentation {
    return new AuthCredentialPresentation(
      Native.ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(
        this.serverPublicParams.getContents(),
        random,
        groupSecretParams.getContents(),
        authCredential.getContents()
      )
    );
  }
}

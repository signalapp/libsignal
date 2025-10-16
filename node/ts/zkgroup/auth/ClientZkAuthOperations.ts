//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import * as Native from '../../Native.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';

import ServerPublicParams from '../ServerPublicParams.js';
import AuthCredentialPresentation from './AuthCredentialPresentation.js';
import AuthCredentialWithPni from './AuthCredentialWithPni.js';
import AuthCredentialWithPniResponse from './AuthCredentialWithPniResponse.js';
import GroupSecretParams from '../groups/GroupSecretParams.js';
import { Aci, Pni } from '../../Address.js';

export default class ClientZkAuthOperations {
  serverPublicParams: ServerPublicParams;

  constructor(serverPublicParams: ServerPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  /**
   * Produces the AuthCredentialWithPni from a server-generated AuthCredentialWithPniResponse.
   *
   * @param redemptionTime - This is provided by the server as an integer, and should be passed through directly.
   */
  receiveAuthCredentialWithPniAsServiceId(
    aci: Aci,
    pni: Pni,
    redemptionTime: number,
    authCredentialResponse: AuthCredentialWithPniResponse
  ): AuthCredentialWithPni {
    return new AuthCredentialWithPni(
      Native.ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(
        this.serverPublicParams,
        aci.getServiceIdFixedWidthBinary(),
        pni.getServiceIdFixedWidthBinary(),
        redemptionTime,
        authCredentialResponse.getContents()
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
    random: Uint8Array,
    groupSecretParams: GroupSecretParams,
    authCredential: AuthCredentialWithPni
  ): AuthCredentialPresentation {
    return new AuthCredentialPresentation(
      Native.ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(
        this.serverPublicParams,
        random,
        groupSecretParams.getContents(),
        authCredential.getContents()
      )
    );
  }
}

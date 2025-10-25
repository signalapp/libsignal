//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';
import { RANDOM_LENGTH } from '../internal/Constants.js';
import * as Native from '../../Native.js';

import ServerSecretParams from '../ServerSecretParams.js';
import AuthCredentialPresentation from './AuthCredentialPresentation.js';
import AuthCredentialWithPniResponse from './AuthCredentialWithPniResponse.js';
import GroupPublicParams from '../groups/GroupPublicParams.js';
import { Aci, Pni } from '../../Address.js';

export default class ServerZkAuthOperations {
  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueAuthCredentialWithPniZkc(
    aci: Aci,
    pni: Pni,
    redemptionTime: number
  ): AuthCredentialWithPniResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueAuthCredentialWithPniZkcWithRandom(
      random,
      aci,
      pni,
      redemptionTime
    );
  }

  issueAuthCredentialWithPniZkcWithRandom(
    random: Uint8Array,
    aci: Aci,
    pni: Pni,
    redemptionTime: number
  ): AuthCredentialWithPniResponse {
    return new AuthCredentialWithPniResponse(
      Native.ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic(
        this.serverSecretParams,
        random,
        aci.getServiceIdFixedWidthBinary(),
        pni.getServiceIdFixedWidthBinary(),
        redemptionTime
      )
    );
  }

  verifyAuthCredentialPresentation(
    groupPublicParams: GroupPublicParams,
    authCredentialPresentation: AuthCredentialPresentation,
    now: Date = new Date()
  ): void {
    Native.ServerSecretParams_VerifyAuthCredentialPresentation(
      this.serverSecretParams,
      groupPublicParams.getContents(),
      authCredentialPresentation.getContents(),
      Math.floor(now.getTime() / 1000)
    );
  }
}

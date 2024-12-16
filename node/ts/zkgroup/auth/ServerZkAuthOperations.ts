//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import ServerSecretParams from '../ServerSecretParams';
import AuthCredentialPresentation from './AuthCredentialPresentation';
import AuthCredentialWithPniResponse from './AuthCredentialWithPniResponse';
import GroupPublicParams from '../groups/GroupPublicParams';
import { Aci, Pni } from '../../Address';

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
    random: Buffer,
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

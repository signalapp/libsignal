//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import ServerSecretParams from '../ServerSecretParams';
import AuthCredentialResponse from './AuthCredentialResponse';
import AuthCredentialPresentation from './AuthCredentialPresentation';
import AuthCredentialWithPniResponse from './AuthCredentialWithPniResponse';
import GroupPublicParams from '../groups/GroupPublicParams';
import { Aci, Pni } from '../../Address';

export default class ServerZkAuthOperations {
  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueAuthCredential(
    aci: Aci,
    redemptionTime: number
  ): AuthCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueAuthCredentialWithRandom(random, aci, redemptionTime);
  }

  issueAuthCredentialWithRandom(
    random: Buffer,
    aci: Aci,
    redemptionTime: number
  ): AuthCredentialResponse {
    return new AuthCredentialResponse(
      Native.ServerSecretParams_IssueAuthCredentialDeterministic(
        this.serverSecretParams.getContents(),
        random,
        aci.getServiceIdFixedWidthBinary(),
        redemptionTime
      )
    );
  }

  issueAuthCredentialWithPniAsServiceId(
    aci: Aci,
    pni: Pni,
    redemptionTime: number
  ): AuthCredentialWithPniResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueAuthCredentialWithPniAsServiceIdWithRandom(
      random,
      aci,
      pni,
      redemptionTime
    );
  }

  issueAuthCredentialWithPniAsServiceIdWithRandom(
    random: Buffer,
    aci: Aci,
    pni: Pni,
    redemptionTime: number
  ): AuthCredentialWithPniResponse {
    return new AuthCredentialWithPniResponse(
      Native.ServerSecretParams_IssueAuthCredentialWithPniAsServiceIdDeterministic(
        this.serverSecretParams.getContents(),
        random,
        aci.getServiceIdFixedWidthBinary(),
        pni.getServiceIdFixedWidthBinary(),
        redemptionTime
      )
    );
  }

  issueAuthCredentialWithPniAsAci(
    aci: Aci,
    pni: Pni,
    redemptionTime: number
  ): AuthCredentialWithPniResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueAuthCredentialWithPniAsAciWithRandom(
      random,
      aci,
      pni,
      redemptionTime
    );
  }

  issueAuthCredentialWithPniAsAciWithRandom(
    random: Buffer,
    aci: Aci,
    pni: Pni,
    redemptionTime: number
  ): AuthCredentialWithPniResponse {
    return new AuthCredentialWithPniResponse(
      Native.ServerSecretParams_IssueAuthCredentialWithPniAsAciDeterministic(
        this.serverSecretParams.getContents(),
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
      this.serverSecretParams.getContents(),
      groupPublicParams.getContents(),
      authCredentialPresentation.getContents(),
      Math.floor(now.getTime() / 1000)
    );
  }
}

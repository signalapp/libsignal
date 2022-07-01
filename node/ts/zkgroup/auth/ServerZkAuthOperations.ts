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
import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class ServerZkAuthOperations {
  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueAuthCredential(
    uuid: UUIDType,
    redemptionTime: number
  ): AuthCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueAuthCredentialWithRandom(random, uuid, redemptionTime);
  }

  issueAuthCredentialWithRandom(
    random: Buffer,
    uuid: UUIDType,
    redemptionTime: number
  ): AuthCredentialResponse {
    return new AuthCredentialResponse(
      Native.ServerSecretParams_IssueAuthCredentialDeterministic(
        this.serverSecretParams.getContents(),
        random,
        fromUUID(uuid),
        redemptionTime
      )
    );
  }

  issueAuthCredentialWithPni(
    aci: UUIDType,
    pni: UUIDType,
    redemptionTime: number
  ): AuthCredentialWithPniResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueAuthCredentialWithPniWithRandom(
      random,
      aci,
      pni,
      redemptionTime
    );
  }

  issueAuthCredentialWithPniWithRandom(
    random: Buffer,
    aci: UUIDType,
    pni: UUIDType,
    redemptionTime: number
  ): AuthCredentialWithPniResponse {
    return new AuthCredentialWithPniResponse(
      Native.ServerSecretParams_IssueAuthCredentialWithPniDeterministic(
        this.serverSecretParams.getContents(),
        random,
        fromUUID(aci),
        fromUUID(pni),
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

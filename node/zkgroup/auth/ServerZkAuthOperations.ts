//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import { RANDOM_LENGTH } from '../internal/Constants';
import NativeImpl from '../../NativeImpl';

import ServerSecretParams from '../ServerSecretParams';
import AuthCredentialResponse from './AuthCredentialResponse';
import AuthCredentialPresentation from './AuthCredentialPresentation';
import GroupPublicParams from '../groups/GroupPublicParams';
import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class ServerZkAuthOperations {

  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueAuthCredential(uuid: UUIDType, redemptionTime: number): AuthCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueAuthCredentialWithRandom(random, uuid, redemptionTime);
  }

  issueAuthCredentialWithRandom(random: Buffer, uuid: UUIDType, redemptionTime: number): AuthCredentialResponse {
    return new AuthCredentialResponse(NativeImpl.ServerSecretParams_IssueAuthCredentialDeterministic(this.serverSecretParams.getContents(), random, fromUUID(uuid), redemptionTime));
  }

  verifyAuthCredentialPresentation(groupPublicParams: GroupPublicParams, authCredentialPresentation: AuthCredentialPresentation) {
    NativeImpl.ServerSecretParams_VerifyAuthCredentialPresentation(this.serverSecretParams.getContents(), groupPublicParams.getContents(), authCredentialPresentation.getContents());
  }

}

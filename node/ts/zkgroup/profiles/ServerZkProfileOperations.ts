//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';
import * as Native from '../../Native.js';
import { RANDOM_LENGTH } from '../internal/Constants.js';

import ServerSecretParams from '../ServerSecretParams.js';
import GroupPublicParams from '../groups/GroupPublicParams.js';

import ExpiringProfileKeyCredentialResponse from './ExpiringProfileKeyCredentialResponse.js';
import ProfileKeyCommitment from './ProfileKeyCommitment.js';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation.js';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest.js';
import { Aci } from '../../Address.js';

export default class ServerZkProfileOperations {
  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueExpiringProfileKeyCredential(
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    userId: Aci,
    profileKeyCommitment: ProfileKeyCommitment,
    expirationInSeconds: number
  ): ExpiringProfileKeyCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueExpiringProfileKeyCredentialWithRandom(
      random,
      profileKeyCredentialRequest,
      userId,
      profileKeyCommitment,
      expirationInSeconds
    );
  }

  issueExpiringProfileKeyCredentialWithRandom(
    random: Uint8Array,
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    userId: Aci,
    profileKeyCommitment: ProfileKeyCommitment,
    expirationInSeconds: number
  ): ExpiringProfileKeyCredentialResponse {
    return new ExpiringProfileKeyCredentialResponse(
      Native.ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(
        this.serverSecretParams,
        random,
        profileKeyCredentialRequest.getContents(),
        userId.getServiceIdFixedWidthBinary(),
        profileKeyCommitment.getContents(),
        expirationInSeconds
      )
    );
  }

  verifyProfileKeyCredentialPresentation(
    groupPublicParams: GroupPublicParams,
    profileKeyCredentialPresentation: ProfileKeyCredentialPresentation,
    now: Date = new Date()
  ): void {
    Native.ServerSecretParams_VerifyProfileKeyCredentialPresentation(
      this.serverSecretParams,
      groupPublicParams.getContents(),
      profileKeyCredentialPresentation.getContents(),
      Math.floor(now.getTime() / 1000)
    );
  }
}

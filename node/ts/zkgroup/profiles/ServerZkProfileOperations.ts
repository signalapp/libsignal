//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import * as Native from '../../../Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import ServerSecretParams from '../ServerSecretParams';

import ProfileKeyCredentialResponse from './ProfileKeyCredentialResponse';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';
import ProfileKeyCommitment from './ProfileKeyCommitment';
import GroupPublicParams from '../groups/GroupPublicParams';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';

import { UUIDType, fromUUID } from '../internal/UUIDUtil';

export default class ServerZkProfileOperations {
  serverSecretParams: ServerSecretParams;

  constructor(serverSecretParams: ServerSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  issueProfileKeyCredential(
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    uuid: UUIDType,
    profileKeyCommitment: ProfileKeyCommitment
  ): ProfileKeyCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueProfileKeyCredentialWithRandom(
      random,
      profileKeyCredentialRequest,
      uuid,
      profileKeyCommitment
    );
  }

  issueProfileKeyCredentialWithRandom(
    random: Buffer,
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    uuid: UUIDType,
    profileKeyCommitment: ProfileKeyCommitment
  ): ProfileKeyCredentialResponse {
    return new ProfileKeyCredentialResponse(
      Native.ServerSecretParams_IssueProfileKeyCredentialDeterministic(
        this.serverSecretParams.getContents(),
        random,
        profileKeyCredentialRequest.getContents(),
        fromUUID(uuid),
        profileKeyCommitment.getContents()
      )
    );
  }

  verifyProfileKeyCredentialPresentation(
    groupPublicParams: GroupPublicParams,
    profileKeyCredentialPresentation: ProfileKeyCredentialPresentation
  ): void {
    Native.ServerSecretParams_VerifyProfileKeyCredentialPresentation(
      this.serverSecretParams.getContents(),
      groupPublicParams.getContents(),
      profileKeyCredentialPresentation.getContents()
    );
  }
}

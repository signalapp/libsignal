//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import * as Native from '../../../Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import ServerSecretParams from '../ServerSecretParams';
import GroupPublicParams from '../groups/GroupPublicParams';

import ExpiringProfileKeyCredentialResponse from './ExpiringProfileKeyCredentialResponse';
import PniCredentialPresentation from './PniCredentialPresentation';
import PniCredentialResponse from './PniCredentialResponse';
import ProfileKeyCommitment from './ProfileKeyCommitment';
import ProfileKeyCredentialPresentation from './ProfileKeyCredentialPresentation';
import ProfileKeyCredentialResponse from './ProfileKeyCredentialResponse';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';

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

  issueExpiringProfileKeyCredential(
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    uuid: UUIDType,
    profileKeyCommitment: ProfileKeyCommitment,
    expirationInSeconds: number
  ): ExpiringProfileKeyCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issueExpiringProfileKeyCredentialWithRandom(
      random,
      profileKeyCredentialRequest,
      uuid,
      profileKeyCommitment,
      expirationInSeconds
    );
  }

  issueExpiringProfileKeyCredentialWithRandom(
    random: Buffer,
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    uuid: UUIDType,
    profileKeyCommitment: ProfileKeyCommitment,
    expirationInSeconds: number
  ): ExpiringProfileKeyCredentialResponse {
    return new ExpiringProfileKeyCredentialResponse(
      Native.ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(
        this.serverSecretParams.getContents(),
        random,
        profileKeyCredentialRequest.getContents(),
        fromUUID(uuid),
        profileKeyCommitment.getContents(),
        expirationInSeconds
      )
    );
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential
   */
  issuePniCredential(
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    aci: UUIDType,
    pni: UUIDType,
    profileKeyCommitment: ProfileKeyCommitment
  ): PniCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);

    return this.issuePniCredentialWithRandom(
      random,
      profileKeyCredentialRequest,
      aci,
      pni,
      profileKeyCommitment
    );
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential
   */
  issuePniCredentialWithRandom(
    random: Buffer,
    profileKeyCredentialRequest: ProfileKeyCredentialRequest,
    aci: UUIDType,
    pni: UUIDType,
    profileKeyCommitment: ProfileKeyCommitment
  ): PniCredentialResponse {
    return new PniCredentialResponse(
      Native.ServerSecretParams_IssuePniCredentialDeterministic(
        this.serverSecretParams.getContents(),
        random,
        profileKeyCredentialRequest.getContents(),
        fromUUID(aci),
        fromUUID(pni),
        profileKeyCommitment.getContents()
      )
    );
  }

  verifyProfileKeyCredentialPresentation(
    groupPublicParams: GroupPublicParams,
    profileKeyCredentialPresentation: ProfileKeyCredentialPresentation,
    now: Date = new Date()
  ): void {
    Native.ServerSecretParams_VerifyProfileKeyCredentialPresentation(
      this.serverSecretParams.getContents(),
      groupPublicParams.getContents(),
      profileKeyCredentialPresentation.getContents(),
      Math.floor(now.getTime() / 1000)
    );
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential
   */
  verifyPniCredentialPresentation(
    groupPublicParams: GroupPublicParams,
    presentation: PniCredentialPresentation
  ): void {
    Native.ServerSecretParams_VerifyPniCredentialPresentation(
      this.serverSecretParams.getContents(),
      groupPublicParams.getContents(),
      presentation.getContents()
    );
  }
}

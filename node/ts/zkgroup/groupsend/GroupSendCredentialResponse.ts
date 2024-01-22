//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import GroupSendCredential from './GroupSendCredential';
import GroupSecretParams from '../groups/GroupSecretParams';
import ServerSecretParams from '../ServerSecretParams';
import ServerPublicParams from '../ServerPublicParams';
import UuidCiphertext from '../groups/UuidCiphertext';
import { Aci, ServiceId } from '../../Address';

// For docs
import type GroupSendCredentialPresentation from './GroupSendCredentialPresentation';
import type { VerificationFailedError } from '../../Errors';

/**
 * The issuance of a credential indicating membership in a group, based on the set of *other* users
 * in the group with you.
 *
 * Follows the usual zkgroup pattern of "issue response -> receive response -> present credential ->
 * verify presentation".
 *
 * @see {@link GroupSendCredential}
 * @see {@link GroupSendCredentialPresentation}
 */
export default class GroupSendCredentialResponse extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.GroupSendCredentialResponse_CheckValidContents);
  }

  private static defaultExpiration(): Date {
    const expirationInSeconds =
      Native.GroupSendCredentialResponse_DefaultExpirationBasedOnCurrentTime();
    return new Date(expirationInSeconds * 1000);
  }

  /**
   * Issues a new credential stating that `requestingMember` is a member of a group containing
   * `groupMembers`.
   *
   * `groupMembers` should include `requestingMember` as well.
   */
  static issueCredential(
    groupMembers: UuidCiphertext[],
    requestingMember: UuidCiphertext,
    params: ServerSecretParams
  ): GroupSendCredentialResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueCredentialWithExpirationAndRandom(
      groupMembers,
      requestingMember,
      this.defaultExpiration(),
      params,
      random
    );
  }

  /**
   * Issues a new credential stating that `requestingMember` is a member of a group containing
   * `groupMembers`, with an explicity-chosen expiration and source of randomness.
   *
   * Should only be used for testing purposes.
   *
   * @see {@link GroupSendCredentialResponse#issueCredential}
   */
  static issueCredentialWithExpirationAndRandom(
    groupMembers: UuidCiphertext[],
    requestingMember: UuidCiphertext,
    expiration: Date,
    params: ServerSecretParams,
    random: Buffer
  ): GroupSendCredentialResponse {
    return new GroupSendCredentialResponse(
      Native.GroupSendCredentialResponse_IssueDeterministic(
        UuidCiphertext.serializeAndConcatenate(groupMembers),
        requestingMember.contents,
        Math.floor(expiration.getTime() / 1000),
        params.contents,
        random
      )
    );
  }

  /**
   * Receives, validates, and extracts the credential from a response.
   *
   * Note that the `receive` operation is provided for both {@link ServiceId}s and
   * {@link UuidCiphertext}s. If you already have the ciphertexts for the group members available,
   * {@link GroupSendCredentialResponse#receiveWithCiphertexts} will be *significantly* faster; if
   * you don't, this method is faster than generating the ciphertexts and throwing them away
   * afterwards.
   *
   * `localUser` should be included in `groupMembers`.
   *
   * @throws {VerificationFailedError} if the credential is not valid for any reason
   */
  receive(
    groupMembers: ServiceId[],
    localUser: Aci,
    serverParams: ServerPublicParams,
    groupParams: GroupSecretParams,
    now: Date = new Date()
  ): GroupSendCredential {
    return new GroupSendCredential(
      Native.GroupSendCredentialResponse_Receive(
        this.contents,
        ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
        localUser.getServiceIdFixedWidthBinary(),
        Math.floor(now.getTime() / 1000),
        serverParams.contents,
        groupParams.contents
      )
    );
  }

  /**
   * Receives, validates, and extracts the credential from a response.
   *
   * Note that the `receive` operation is provided for both {@link ServiceId}s and
   * {@link UuidCiphertext}s. If you already have the ciphertexts for the group members available,
   * this method will be *significantly* faster; if you don't,
   * {@link GroupSendCredentialResponse#receive} is faster than generating the ciphertexts and
   * throwing them away afterwards.
   *
   * `localUser` should be included in `groupMembers`.
   *
   * @throws {VerificationFailedError} if the credential is not valid for any reason
   */
  receiveWithCiphertexts(
    groupMembers: UuidCiphertext[],
    localUser: UuidCiphertext,
    serverParams: ServerPublicParams,
    groupParams: GroupSecretParams,
    now: Date = new Date()
  ): GroupSendCredential {
    return new GroupSendCredential(
      Native.GroupSendCredentialResponse_ReceiveWithCiphertexts(
        this.contents,
        UuidCiphertext.serializeAndConcatenate(groupMembers),
        localUser.contents,
        Math.floor(now.getTime() / 1000),
        serverParams.contents,
        groupParams.contents
      )
    );
  }
}

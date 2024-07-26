//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray, { UNCHECKED_AND_UNCLONED } from '../internal/ByteArray';
import * as Native from '../../../Native';
import { RANDOM_LENGTH } from '../internal/Constants';

import GroupSecretParams from '../groups/GroupSecretParams';
import ServerPublicParams from '../ServerPublicParams';
import UuidCiphertext from '../groups/UuidCiphertext';
import { Aci, ServiceId } from '../../Address';
import GroupSendDerivedKeyPair from './GroupSendDerivedKeyPair';
import GroupSendEndorsement from './GroupSendEndorsement';

// For docs
import type { VerificationFailedError } from '../../Errors';
import GroupSendFullToken from './GroupSendFullToken';

/**
 * A collection of endorsements known to be valid.
 *
 * The result of the `receive` operations on {@link GroupSendEndorsementsResponse}. Contains an
 * endorsement for each member of the group, in the same order they were originally provided, plus a
 * combined endorsement for "everyone but me", intended for multi-recipient sends.
 */
export type ReceivedEndorsements = {
  endorsements: GroupSendEndorsement[];
  combinedEndorsement: GroupSendEndorsement;
};

/**
 * A set of endorsements of the members in a group, along with a proof of their validity.
 *
 * Issued by the group server based on the group's member ciphertexts. The endorsements will
 * eventually be verified by the chat server in the form of {@link GroupSendFullToken}s. See
 * {@link GroupSendEndorsement} for a full description of the endorsement flow from the client's
 * perspective.
 */
export default class GroupSendEndorsementsResponse extends ByteArray {
  constructor(contents: Buffer) {
    super(contents, Native.GroupSendEndorsementsResponse_CheckValidContents);
  }

  /**
   * Issues a new set of endorsements for `groupMembers`.
   *
   * `groupMembers` should include `requestingUser` as well.
   */
  public static issue(
    groupMembers: UuidCiphertext[],
    keyPair: GroupSendDerivedKeyPair
  ): GroupSendEndorsementsResponse {
    const random = randomBytes(RANDOM_LENGTH);
    return this.issueWithRandom(groupMembers, keyPair, random);
  }

  /**
   * Issues a new set of endorsements for `groupMembers`, with an explicity-chosen expiration and
   * source of randomness.
   *
   * Should only be used for testing purposes.
   *
   * @see {@link GroupSendEndorsementsResponse#issue}
   */
  public static issueWithRandom(
    groupMembers: UuidCiphertext[],
    keyPair: GroupSendDerivedKeyPair,
    random: Buffer
  ): GroupSendEndorsementsResponse {
    return new GroupSendEndorsementsResponse(
      Native.GroupSendEndorsementsResponse_IssueDeterministic(
        UuidCiphertext.serializeAndConcatenate(groupMembers),
        keyPair.contents,
        random
      )
    );
  }

  /** Returns the expiration for the contained endorsements. */
  getExpiration(): Date {
    return new Date(
      1000 * Native.GroupSendEndorsementsResponse_GetExpiration(this.contents)
    );
  }

  /**
   * Receives, validates, and extracts the endorsements from a response.
   *
   * Note that the `receive` operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, {@link
   * #receiveWithCiphertexts} should be faster; if you don't, this method is faster than generating
   * the ciphertexts and throwing them away afterwards.
   *
   * `localUser` should be included in `groupMembers`.
   *
   * @throws {VerificationFailedError} if the endorsements are not valid for any reason
   */
  receiveWithServiceIds(
    groupMembers: ServiceId[],
    localUser: Aci,
    groupParams: GroupSecretParams,
    serverParams: ServerPublicParams,
    now: Date = new Date()
  ): ReceivedEndorsements {
    const endorsementContents =
      Native.GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds(
        this.contents,
        ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
        localUser.getServiceIdFixedWidthBinary(),
        Math.floor(now.getTime() / 1000),
        groupParams.contents,
        serverParams
      );
    const endorsements = endorsementContents.map((next) => {
      // Normally we don't notice the cost of validating just-created zkgroup objects,
      // but in this case we may have up to 1000 of these. Let's assume they're created correctly.
      return new GroupSendEndorsement(next, UNCHECKED_AND_UNCLONED);
    });
    const combinedEndorsement = endorsements.pop();
    if (!combinedEndorsement) {
      throw new Error(
        "GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds didn't produce a combined endorsement"
      );
    }
    return { endorsements, combinedEndorsement };
  }

  /**
   * Receives, validates, and extracts the endorsements from a response.
   *
   * Note that the `receive` operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, this
   * method should be faster; if you don't, {@link #receiveWithServiceIds} is faster than generating
   * the ciphertexts and throwing them away afterwards.
   *
   * `localUser` should be included in `groupMembers`.
   *
   * @throws {VerificationFailedError} if the endorsements are not valid for any reason
   */
  receiveWithCiphertexts(
    groupMembers: UuidCiphertext[],
    localUser: UuidCiphertext,
    serverParams: ServerPublicParams,
    now: Date = new Date()
  ): ReceivedEndorsements {
    const endorsementContents =
      Native.GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts(
        this.contents,
        UuidCiphertext.serializeAndConcatenate(groupMembers),
        localUser.contents,
        Math.floor(now.getTime() / 1000),
        serverParams
      );
    const endorsements = endorsementContents.map((next) => {
      // Normally we don't notice the cost of validating just-created zkgroup objects,
      // but in this case we may have up to 1000 of these. Let's assume they're created correctly.
      return new GroupSendEndorsement(next, UNCHECKED_AND_UNCLONED);
    });
    const combinedEndorsement = endorsements.pop();
    if (!combinedEndorsement) {
      throw new Error(
        "GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts didn't produce a combined endorsement"
      );
    }
    return { endorsements, combinedEndorsement };
  }
}

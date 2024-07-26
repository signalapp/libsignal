//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray, { UNCHECKED_AND_UNCLONED } from '../internal/ByteArray';
import * as Native from '../../../Native';

import GroupSecretParams from '../groups/GroupSecretParams';
import GroupSendFullToken from './GroupSendFullToken';
import GroupSendToken from './GroupSendToken';

// For docs
import type {
  default as GroupSendEndorsementsResponse,
  ReceivedEndorsements,
} from './GroupSendEndorsementsResponse';

/**
 * An endorsement for a user or set of users in a group.
 *
 * GroupSendEndorsements provide a form of authorization by demonstrating that the holder of the
 * endorsement is in a group with a particular user or set of users. They can be
 * [combined]{@link #combine} and [removed]{@link #byRemoving} in a set-like fashion.
 *
 * The endorsement "flow" starts with receiving a {@link GroupSendEndorsementsResponse} from the
 * group server, which contains endorsements for all members in a group (including the local user).
 * The response object provides the single expiration for all the endorsements. From there, the
 * `receive` method produces a {@link ReceivedEndorsements}, which exposes the individual
 * endorsements as well as a combined endorsement for everyone but the local user. Clients should
 * save these endorsements and the expiration with the group state.
 *
 * When it comes time to send a message to an individual user, clients should check to see if they
 * have a {@link GroupSendToken} for that user, and generate and cache one using
 * {@link GroupSendEndorsement#toToken} if not. The token should then be converted to a full token
 * using {@link GroupSendToken#toFullToken}, providing the expiration saved previously. Finally, the
 * serialized full token can be used as authorization in a request to the chat server.
 *
 * Similarly, when it comes time to send a message to the group, clients should start by
 * [removing]{@link #byRemoving} the endorsements of any users they are excluding (say, because they
 * need a Sender Key Distribution Message first), and then converting the resulting endorsement to a
 * token. From there, the token can be converted to a full token and serialized as for an individual
 * send. (Saving the repeated work of converting to a token is left to the clients here; worst case,
 * it's still cheaper than a usual zkgroup presentation.)
 */
export default class GroupSendEndorsement extends ByteArray {
  constructor(contents: Buffer, marker?: typeof UNCHECKED_AND_UNCLONED) {
    super(contents, marker ?? Native.GroupSendEndorsement_CheckValidContents);
  }

  /**
   * Combines several endorsements into one.
   *
   * For example, if you have endorsements to send to Meredith and Aruna individually, then you can
   * combine them to produce an endorsement to send a multi-recipient message to the two of them.
   */
  static combine(endorsements: GroupSendEndorsement[]): GroupSendEndorsement {
    return new GroupSendEndorsement(
      Native.GroupSendEndorsement_Combine(
        endorsements.map((next) => next.contents)
      )
    );
  }

  /**
   * Removes an endorsement (individual or combined) from this combined endorsement.
   *
   * If `this` is *not* a combined endorsement, or `toRemove` includes endorsements that were not
   * combined into `this`, the result will not generate valid tokens.
   */
  byRemoving(toRemove: GroupSendEndorsement): GroupSendEndorsement {
    return new GroupSendEndorsement(
      Native.GroupSendEndorsement_Remove(this.contents, toRemove.contents)
    );
  }

  /**
   * Generates a cacheable token used to authenticate sends.
   *
   * The token is no longer associated with the group; it merely identifies the user or set of users
   * referenced by this endorsement. (Of course, a set of users is a pretty good stand-in for a
   * group.)
   *
   * @see {@link GroupSendToken}
   */
  toToken(groupParams: GroupSecretParams): GroupSendToken {
    return new GroupSendToken(
      Native.GroupSendEndorsement_ToToken(this.contents, groupParams.contents)
    );
  }

  /**
   * Generates a token used to authenticate sends, ready to put in an auth header.
   *
   * `expiration` must be the same expiration that was in the original {@link
   * GroupSendEndorsementsResponse}, or the resulting token will fail to verify.
   *
   * Equivalent to {@link #toToken} followed by {@link GroupSendToken#toFullToken}.
   */
  toFullToken(
    groupParams: GroupSecretParams,
    expiration: Date
  ): GroupSendFullToken {
    return this.toToken(groupParams).toFullToken(expiration);
  }
}

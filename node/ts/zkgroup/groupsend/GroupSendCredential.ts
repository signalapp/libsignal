//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import GroupSendCredentialPresentation from './GroupSendCredentialPresentation';
import type GroupSendCredentialResponse from './GroupSendCredentialResponse'; // for docs
import ServerPublicParams from '../ServerPublicParams';

/**
 * A credential indicating membership in a group, based on the set of *other* users in the
 * group with you.
 *
 * Follows the usual zkgroup pattern of "issue response -> receive response -> present credential
 * -> verify presentation".
 *
 * @see {@link GroupSendCredentialResponse}
 * @see {@link GroupSendCredentialPresentation}
 */
export default class GroupSendCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.GroupSendCredential_CheckValidContents);
  }

  /**
   * Generates a new presentation, so that multiple uses of this credential are harder to link.
   */
  present(serverParams: ServerPublicParams): GroupSendCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);
    return this.presentWithRandom(serverParams, random);
  }

  /**
   * Generates a new presentation with a dedicated source of randomness.
   *
   * Should only be used for testing purposes.
   *
   * @see {@link GroupSendCredential#present}
   */
  presentWithRandom(
    serverParams: ServerPublicParams,
    random: Buffer
  ): GroupSendCredentialPresentation {
    return new GroupSendCredentialPresentation(
      Native.GroupSendCredential_PresentDeterministic(
        this.contents,
        serverParams.contents,
        random
      )
    );
  }
}

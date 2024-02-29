//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

import ServerSecretParams from '../ServerSecretParams';
import { ServiceId } from '../../Address';

// For docs:
import type GroupSendCredential from './GroupSendCredential';
import type GroupSendCredentialResponse from './GroupSendCredentialResponse';
import type { VerificationFailedError } from '../../Errors';

/**
 * A credential presentation indicating membership in a group, based on the set of *other* users in
 * the group with you.
 *
 * Follows the usual zkgroup pattern of "issue response -> receive response -> present credential ->
 * verify presentation".
 *
 * @see {@link GroupSendCredentialResponse}
 * @see {@link GroupSendCredential}
 */
export default class GroupSendCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.GroupSendCredentialPresentation_CheckValidContents);
  }

  /**
   * Verifies that the credential is valid for a group containing the holder and `groupMembers`.
   *
   * @throws {VerificationFailedError} if the credential is not valid for any reason
   */
  verify(
    groupMembers: ServiceId[],
    serverParams: ServerSecretParams,
    now: Date = new Date()
  ): void {
    Native.GroupSendCredentialPresentation_Verify(
      this.contents,
      ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
      Math.floor(now.getTime() / 1000),
      serverParams.contents
    );
  }
}

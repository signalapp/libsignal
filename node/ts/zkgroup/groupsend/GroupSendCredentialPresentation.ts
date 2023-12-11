//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

import ServerSecretParams from '../ServerSecretParams';
import { ServiceId } from '../../Address';

export default class GroupSendCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.GroupSendCredentialPresentation_CheckValidContents);
  }

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

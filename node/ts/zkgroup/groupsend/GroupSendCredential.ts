//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';

import ByteArray from '../internal/ByteArray';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import GroupSendCredentialPresentation from './GroupSendCredentialPresentation';
import ServerPublicParams from '../ServerPublicParams';

export default class GroupSendCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.GroupSendCredential_CheckValidContents);
  }

  present(serverParams: ServerPublicParams): GroupSendCredentialPresentation {
    const random = randomBytes(RANDOM_LENGTH);
    return this.presentWithRandom(serverParams, random);
  }

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

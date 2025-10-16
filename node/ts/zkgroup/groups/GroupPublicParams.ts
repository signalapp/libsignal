//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';
import GroupIdentifier from './GroupIdentifier.js';

export default class GroupPublicParams extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.GroupPublicParams_CheckValidContents);
  }

  getGroupIdentifier(): GroupIdentifier {
    return new GroupIdentifier(
      Native.GroupPublicParams_GetGroupIdentifier(this.contents)
    );
  }
}

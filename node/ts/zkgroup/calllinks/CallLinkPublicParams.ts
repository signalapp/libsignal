//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

export default class CallLinkPublicParams extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.CallLinkPublicParams_CheckValidContents);
  }
}

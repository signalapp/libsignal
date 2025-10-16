//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

export default class ExpiringProfileKeyCredential extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.ExpiringProfileKeyCredential_CheckValidContents);
  }

  getExpirationTime(): Date {
    return new Date(
      1000 *
        Native.ExpiringProfileKeyCredential_GetExpirationTime(this.contents)
    );
  }
}

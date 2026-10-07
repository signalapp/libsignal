//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';

export default class ExpiringProfileKeyCredentialResponse extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Bytes) {
    super(
      contents,
      Native.ExpiringProfileKeyCredentialResponse_CheckValidContents
    );
  }
}

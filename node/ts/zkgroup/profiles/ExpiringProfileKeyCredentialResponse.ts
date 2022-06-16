//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';

export default class ExpiringProfileKeyCredentialResponse extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(
      contents,
      Native.ExpiringProfileKeyCredentialResponse_CheckValidContents
    );
  }
}

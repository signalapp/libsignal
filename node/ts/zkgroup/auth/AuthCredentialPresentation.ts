//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import UuidCiphertext from '../groups/UuidCiphertext';

export default class AuthCredentialPresentation extends ByteArray {
  constructor(contents: Buffer) {
    super(contents, Native.AuthCredentialPresentation_CheckValidContents);
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      Native.AuthCredentialPresentation_GetUuidCiphertext(this.contents)
    );
  }

  getRedemptionTime(): number {
    return Native.AuthCredentialPresentation_GetRedemptionTime(this.contents);
  }
}

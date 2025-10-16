//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';
import UuidCiphertext from '../groups/UuidCiphertext.js';

export default class AuthCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.AuthCredentialPresentation_CheckValidContents);
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      Native.AuthCredentialPresentation_GetUuidCiphertext(this.contents)
    );
  }

  getPniCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      Native.AuthCredentialPresentation_GetPniCiphertext(this.contents)
    );
  }

  getRedemptionTime(): Date {
    return new Date(
      1000 * Native.AuthCredentialPresentation_GetRedemptionTime(this.contents)
    );
  }
}

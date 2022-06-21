//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import UuidCiphertext from '../groups/UuidCiphertext';

export default class AuthCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.AuthCredentialPresentation_CheckValidContents);
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      Native.AuthCredentialPresentation_GetUuidCiphertext(this.contents)
    );
  }

  getPniCiphertext(): UuidCiphertext | null {
    const ciphertextBytes = Native.AuthCredentialPresentation_GetPniCiphertext(
      this.contents
    );
    if (ciphertextBytes === null) {
      return null;
    }
    return new UuidCiphertext(ciphertextBytes);
  }

  getRedemptionTime(): Date {
    return new Date(
      1000 * Native.AuthCredentialPresentation_GetRedemptionTime(this.contents)
    );
  }
}

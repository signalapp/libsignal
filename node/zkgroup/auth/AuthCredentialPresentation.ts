//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import UuidCiphertext from '../groups/UuidCiphertext';

export default class AuthCredentialPresentation extends ByteArray {
  constructor(contents: Buffer) {
    super(contents, NativeImpl.AuthCredentialPresentation_CheckValidContents);
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      NativeImpl.AuthCredentialPresentation_GetUuidCiphertext(this.contents)
    );
  }

  getRedemptionTime(): number {
    return NativeImpl.AuthCredentialPresentation_GetRedemptionTime(
      this.contents
    );
  }
}

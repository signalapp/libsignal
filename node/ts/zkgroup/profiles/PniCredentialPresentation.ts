//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import UuidCiphertext from '../groups/UuidCiphertext';
import ProfileKeyCiphertext from '../groups/ProfileKeyCiphertext';

export default class PniCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.PniCredentialPresentation_CheckValidContents);
  }

  getAciCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      Native.PniCredentialPresentation_GetAciCiphertext(this.contents)
    );
  }

  getPniCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      Native.PniCredentialPresentation_GetPniCiphertext(this.contents)
    );
  }

  getProfileKeyCiphertext(): ProfileKeyCiphertext {
    return new ProfileKeyCiphertext(
      Native.PniCredentialPresentation_GetProfileKeyCiphertext(this.contents)
    );
  }
}

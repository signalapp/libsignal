//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';
import UuidCiphertext from '../groups/UuidCiphertext.js';
import ProfileKeyCiphertext from '../groups/ProfileKeyCiphertext.js';

export default class ProfileKeyCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array) {
    super(contents, Native.ProfileKeyCredentialPresentation_CheckValidContents);
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      Native.ProfileKeyCredentialPresentation_GetUuidCiphertext(this.contents)
    );
  }

  getProfileKeyCiphertext(): ProfileKeyCiphertext {
    return new ProfileKeyCiphertext(
      Native.ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(
        this.contents
      )
    );
  }
}

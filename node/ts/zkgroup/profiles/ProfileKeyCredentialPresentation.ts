//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import UuidCiphertext from '../groups/UuidCiphertext';
import ProfileKeyCiphertext from '../groups/ProfileKeyCiphertext';

export default class ProfileKeyCredentialPresentation extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
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

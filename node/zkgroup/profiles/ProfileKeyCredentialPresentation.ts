//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import UuidCiphertext from '../groups/UuidCiphertext';
import ProfileKeyCiphertext from '../groups/ProfileKeyCiphertext';

export default class ProfileKeyCredentialPresentation extends ByteArray {
  constructor(contents: Buffer) {
    super(
      contents,
      NativeImpl.ProfileKeyCredentialPresentation_CheckValidContents
    );
  }

  getUuidCiphertext(): UuidCiphertext {
    return new UuidCiphertext(
      NativeImpl.ProfileKeyCredentialPresentation_GetUuidCiphertext(
        this.contents
      )
    );
  }

  getProfileKeyCiphertext(): ProfileKeyCiphertext {
    return new ProfileKeyCiphertext(
      NativeImpl.ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(
        this.contents
      )
    );
  }
}

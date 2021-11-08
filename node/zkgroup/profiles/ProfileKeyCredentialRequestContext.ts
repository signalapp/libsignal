//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';

export default class ProfileKeyCredentialRequestContext extends ByteArray {
  constructor(contents: Buffer) {
    super(
      contents,
      NativeImpl.ProfileKeyCredentialRequestContext_CheckValidContents
    );
  }

  getRequest(): ProfileKeyCredentialRequest {
    return new ProfileKeyCredentialRequest(
      NativeImpl.ProfileKeyCredentialRequestContext_GetRequest(this.contents)
    );
  }
}

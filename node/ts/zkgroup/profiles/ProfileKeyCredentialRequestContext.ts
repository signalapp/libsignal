//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';

export default class ProfileKeyCredentialRequestContext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(
      contents,
      Native.ProfileKeyCredentialRequestContext_CheckValidContents
    );
  }

  getRequest(): ProfileKeyCredentialRequest {
    return new ProfileKeyCredentialRequest(
      Native.ProfileKeyCredentialRequestContext_GetRequest(this.contents)
    );
  }
}

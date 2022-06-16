//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import * as Native from '../../../Native';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';

export default class PniCredentialRequestContext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Buffer) {
    super(contents, Native.PniCredentialRequestContext_CheckValidContents);
  }

  getRequest(): ProfileKeyCredentialRequest {
    return new ProfileKeyCredentialRequest(
      Native.PniCredentialRequestContext_GetRequest(this.contents)
    );
  }
}

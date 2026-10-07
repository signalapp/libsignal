//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import ByteArray from '../internal/ByteArray.js';
import * as Native from '../../Native.js';
import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest.js';

export default class ProfileKeyCredentialRequestContext extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Bytes) {
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

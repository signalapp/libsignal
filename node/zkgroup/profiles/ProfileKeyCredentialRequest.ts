//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ProfileKeyCredentialRequest extends ByteArray {

  static SIZE = 329;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCredentialRequest.SIZE, true);
    NativeImpl.ProfileKeyCredentialRequest_CheckValidContents(contents);
  }

}

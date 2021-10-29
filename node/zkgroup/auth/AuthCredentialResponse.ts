//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';
export default class AuthCredentialResponse extends ByteArray {
  static SIZE = 361;

  constructor(contents: Buffer) {
    super(contents, AuthCredentialResponse.SIZE, true);
    NativeImpl.AuthCredentialResponse_CheckValidContents(contents);
  }
}

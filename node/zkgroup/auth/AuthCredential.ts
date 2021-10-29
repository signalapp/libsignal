//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class AuthCredential extends ByteArray {
  static SIZE = 181;

  constructor(contents: Buffer) {
    super(contents, AuthCredential.SIZE, true);
    NativeImpl.AuthCredential_CheckValidContents(contents);
  }
}

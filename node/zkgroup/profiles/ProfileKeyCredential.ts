//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ProfileKeyCredential extends ByteArray {

  static SIZE = 145;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCredential.SIZE, true);
    NativeImpl.ProfileKeyCredential_CheckValidContents(contents);
  }
}

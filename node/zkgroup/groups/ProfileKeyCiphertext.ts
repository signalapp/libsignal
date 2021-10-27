//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from '../internal/ByteArray';
import NativeImpl from '../../NativeImpl';

export default class ProfileKeyCiphertext extends ByteArray {

  static SIZE = 65;

  constructor(contents: Buffer) {
    super(contents, ProfileKeyCiphertext.SIZE, true);
    NativeImpl.ProfileKeyCiphertext_CheckValidContents(contents);
  }
}

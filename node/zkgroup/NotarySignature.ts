//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from './internal/ByteArray';

export default class NotarySignature extends ByteArray {
  static SIZE = 64;

  constructor(contents: Buffer) {
    super(contents, NotarySignature.checkLength(NotarySignature.SIZE));
  }
}

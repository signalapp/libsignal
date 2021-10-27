//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import ByteArray from './internal/ByteArray';
import NativeImpl from '../NativeImpl';
import NotarySignature from './NotarySignature';

export default class ServerPublicParams extends ByteArray {

  static SIZE = 225;

  constructor (contents: Buffer)  {
    super(contents, ServerPublicParams.SIZE, true);
    NativeImpl.ServerPublicParams_CheckValidContents(contents);
  }

  verifySignature(message: Buffer, notarySignature: NotarySignature) {
    NativeImpl.ServerPublicParams_VerifySignature(this.contents, message, notarySignature.getContents());
  }

}



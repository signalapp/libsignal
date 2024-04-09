//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../../Native';
import NotarySignature from './NotarySignature';

export default class ServerPublicParams {
  readonly _nativeHandle: Native.ServerPublicParams;

  constructor(contents: Buffer | Native.ServerPublicParams) {
    if (contents instanceof Buffer) {
      this._nativeHandle = Native.ServerPublicParams_Deserialize(contents);
    } else {
      this._nativeHandle = contents;
    }
  }

  verifySignature(message: Buffer, notarySignature: NotarySignature): void {
    Native.ServerPublicParams_VerifySignature(
      this,
      message,
      notarySignature.getContents()
    );
  }

  serialize(): Buffer {
    return Native.ServerPublicParams_Serialize(this);
  }
}

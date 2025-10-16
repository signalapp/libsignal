//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native.js';
import NotarySignature from './NotarySignature.js';

export default class ServerPublicParams {
  readonly _nativeHandle: Native.ServerPublicParams;

  constructor(contents: Uint8Array | Native.ServerPublicParams) {
    if (contents instanceof Uint8Array) {
      this._nativeHandle = Native.ServerPublicParams_Deserialize(contents);
    } else {
      this._nativeHandle = contents;
    }
  }

  /**
   * Get the serialized form of the params' endorsement key.
   *
   * Allows decoupling RingRTC's use of endorsements from libsignal's.
   */
  getEndorsementPublicKey(): Uint8Array {
    return Native.ServerPublicParams_GetEndorsementPublicKey(this);
  }

  verifySignature(message: Uint8Array, notarySignature: NotarySignature): void {
    Native.ServerPublicParams_VerifySignature(
      this,
      message,
      notarySignature.getContents()
    );
  }

  serialize(): Uint8Array {
    return Native.ServerPublicParams_Serialize(this);
  }
}

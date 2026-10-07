//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import * as Native from '../Native.js';
import NotarySignature from './NotarySignature.js';

export default class ServerPublicParams {
  readonly _nativeHandle: Native.ServerPublicParams;

  constructor(contents: Bytes | Native.ServerPublicParams) {
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
  getEndorsementPublicKey(): Bytes {
    return Native.ServerPublicParams_GetEndorsementPublicKey(this);
  }

  verifySignature(message: Bytes, notarySignature: NotarySignature): void {
    Native.ServerPublicParams_VerifySignature(
      this,
      message,
      notarySignature.getContents()
    );
  }

  serialize(): Bytes {
    return Native.ServerPublicParams_Serialize(this);
  }
}

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native.js';

export interface CiphertextMessageConvertible {
  asCiphertextMessage: () => CiphertextMessage;
}

export class CiphertextMessage {
  readonly _nativeHandle: Native.CiphertextMessage;

  private constructor(nativeHandle: Native.CiphertextMessage) {
    this._nativeHandle = nativeHandle;
  }

  static _fromNativeHandle(
    nativeHandle: Native.CiphertextMessage
  ): CiphertextMessage {
    return new CiphertextMessage(nativeHandle);
  }

  static from(message: CiphertextMessageConvertible): CiphertextMessage {
    return message.asCiphertextMessage();
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.CiphertextMessage_Serialize(this);
  }

  type(): number {
    return Native.CiphertextMessage_Type(this);
  }
}

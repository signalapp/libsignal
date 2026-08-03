//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native.js';

export class KEMPublicKey {
  readonly _nativeHandle: Native.KyberPublicKey;

  private constructor(handle: Native.KyberPublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberPublicKey): KEMPublicKey {
    return new KEMPublicKey(handle);
  }

  static deserialize(buf: Uint8Array<ArrayBuffer>): KEMPublicKey {
    return new KEMPublicKey(Native.KyberPublicKey_Deserialize(buf));
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.KyberPublicKey_Serialize(this);
  }
}

export class KEMSecretKey {
  readonly _nativeHandle: Native.KyberSecretKey;

  private constructor(handle: Native.KyberSecretKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberSecretKey): KEMSecretKey {
    return new KEMSecretKey(handle);
  }

  static deserialize(buf: Uint8Array<ArrayBuffer>): KEMSecretKey {
    return new KEMSecretKey(Native.KyberSecretKey_Deserialize(buf));
  }

  serialize(): Uint8Array<ArrayBuffer> {
    return Native.KyberSecretKey_Serialize(this);
  }
}

export class KEMKeyPair {
  readonly _nativeHandle: Native.KyberKeyPair;

  private constructor(handle: Native.KyberKeyPair) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberKeyPair): KEMKeyPair {
    return new KEMKeyPair(handle);
  }

  static generate(): KEMKeyPair {
    return new KEMKeyPair(Native.KyberKeyPair_Generate());
  }

  getPublicKey(): KEMPublicKey {
    return KEMPublicKey._fromNativeHandle(
      Native.KyberKeyPair_GetPublicKey(this)
    );
  }

  getSecretKey(): KEMSecretKey {
    return KEMSecretKey._fromNativeHandle(
      Native.KyberKeyPair_GetSecretKey(this)
    );
  }
}

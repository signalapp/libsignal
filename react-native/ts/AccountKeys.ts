//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native';

function getNative(): any {
  return (globalThis as any).__libsignal_native;
}

/**
 * An account entropy pool for deriving backup keys and other secrets.
 */
export class AccountEntropyPool {
  readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  /**
   * Generate a new random account entropy pool.
   */
  static generate(): AccountEntropyPool {
    const n = getNative();
    return new AccountEntropyPool(n.AccountEntropyPool_Generate());
  }

  /**
   * Derive a backup key from this entropy pool.
   */
  deriveBackupKey(): Uint8Array {
    const n = getNative();
    return n.AccountEntropyPool_DeriveBackupKey(this.value);
  }

  toString(): string {
    return this.value;
  }
}

/**
 * Kyber (post-quantum) public key for key encapsulation.
 */
export class KEMPublicKey {
  readonly _nativeHandle: Native.KyberPublicKey;

  private constructor(handle: Native.KyberPublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberPublicKey): KEMPublicKey {
    return new KEMPublicKey(handle);
  }

  /**
   * Deserialize from bytes.
   */
  static deserialize(buf: Uint8Array): KEMPublicKey {
    const n = getNative();
    return new KEMPublicKey(n.KyberPublicKey_Deserialize(buf));
  }

  /**
   * Serialize to bytes.
   */
  serialize(): Uint8Array {
    const n = getNative();
    return n.KyberPublicKey_Serialize(this._nativeHandle);
  }
}

/**
 * Kyber (post-quantum) secret key for key encapsulation.
 */
export class KEMSecretKey {
  readonly _nativeHandle: Native.KyberSecretKey;

  private constructor(handle: Native.KyberSecretKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.KyberSecretKey): KEMSecretKey {
    return new KEMSecretKey(handle);
  }

  /**
   * Deserialize from bytes.
   */
  static deserialize(buf: Uint8Array): KEMSecretKey {
    const n = getNative();
    return new KEMSecretKey(n.KyberSecretKey_Deserialize(buf));
  }

  /**
   * Serialize to bytes.
   */
  serialize(): Uint8Array {
    const n = getNative();
    return n.KyberSecretKey_Serialize(this._nativeHandle);
  }
}

/**
 * A Kyber key pair (public + secret key).
 */
export class KEMKeyPair {
  readonly publicKey: KEMPublicKey;
  readonly secretKey: KEMSecretKey;

  private constructor(publicKey: KEMPublicKey, secretKey: KEMSecretKey) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  /**
   * Generate a new Kyber-1024 key pair.
   */
  static generate(): KEMKeyPair {
    const n = getNative();
    const handle = n.KyberKeyPair_Generate();
    return new KEMKeyPair(
      KEMPublicKey._fromNativeHandle(n.KyberKeyPair_GetPublicKey(handle)),
      KEMSecretKey._fromNativeHandle(n.KyberKeyPair_GetSecretKey(handle))
    );
  }
}

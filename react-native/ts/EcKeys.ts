//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native';

type NativeInterface = ReturnType<typeof getNative>;

function getNative(): any {
  return (globalThis as any).__libsignal_native;
}

/**
 * An elliptic curve public key (Curve25519).
 */
export class PublicKey {
  readonly _nativeHandle: Native.PublicKey;

  private constructor(handle: Native.PublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  /**
   * Deserialize a public key from its 33-byte serialized form.
   */
  static deserialize(buf: Uint8Array): PublicKey {
    const n = getNative();
    return new PublicKey(n.PublicKey_Deserialize(buf));
  }

  /**
   * Serialize this public key to its 33-byte form.
   */
  serialize(): Uint8Array {
    const n = getNative();
    return n.PublicKey_Serialize(this._nativeHandle);
  }

  /**
   * Get the raw 32-byte public key bytes (without the type prefix).
   */
  getPublicKeyBytes(): Uint8Array {
    const n = getNative();
    return n.PublicKey_GetPublicKeyBytes(this._nativeHandle);
  }

  /**
   * Check if two public keys are equal.
   */
  equals(other: PublicKey): boolean {
    const n = getNative();
    return n.PublicKey_Equals(this._nativeHandle, other._nativeHandle);
  }

  /**
   * Verify a signature against a message using this public key.
   */
  verify(msg: Uint8Array, sig: Uint8Array): boolean {
    const n = getNative();
    return n.PublicKey_Verify(this._nativeHandle, msg, sig);
  }

  /**
   * Verify an alternate identity signature.
   */
  verifyAlternateIdentity(other: PublicKey, signature: Uint8Array): boolean {
    const n = getNative();
    return n.IdentityKey_VerifyAlternateIdentity(
      this._nativeHandle,
      other._nativeHandle,
      signature
    );
  }
}

/**
 * An elliptic curve private key (Curve25519).
 */
export class PrivateKey {
  readonly _nativeHandle: Native.PrivateKey;

  private constructor(handle: Native.PrivateKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.PrivateKey): PrivateKey {
    return new PrivateKey(handle);
  }

  /**
   * Generate a new random private key.
   */
  static generate(): PrivateKey {
    const n = getNative();
    return new PrivateKey(n.PrivateKey_Generate());
  }

  /**
   * Deserialize a private key from its serialized form.
   */
  static deserialize(buf: Uint8Array): PrivateKey {
    const n = getNative();
    return new PrivateKey(n.PrivateKey_Deserialize(buf));
  }

  /**
   * Serialize this private key.
   */
  serialize(): Uint8Array {
    const n = getNative();
    return n.PrivateKey_Serialize(this._nativeHandle);
  }

  /**
   * Sign a message with this private key (Ed25519).
   */
  sign(msg: Uint8Array): Uint8Array {
    const n = getNative();
    return n.PrivateKey_Sign(this._nativeHandle, msg);
  }

  /**
   * Perform ECDH key agreement with a public key.
   */
  agree(otherKey: PublicKey): Uint8Array {
    const n = getNative();
    return n.PrivateKey_Agree(this._nativeHandle, otherKey._nativeHandle);
  }

  /**
   * Get the corresponding public key.
   */
  getPublicKey(): PublicKey {
    const n = getNative();
    return PublicKey._fromNativeHandle(
      n.PrivateKey_GetPublicKey(this._nativeHandle)
    );
  }
}

/**
 * An identity key pair (public + private key).
 */
export class IdentityKeyPair {
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;

  constructor(publicKey: PublicKey, privateKey: PrivateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * Generate a new identity key pair.
   */
  static generate(): IdentityKeyPair {
    const privateKey = PrivateKey.generate();
    return new IdentityKeyPair(privateKey.getPublicKey(), privateKey);
  }

  /**
   * Serialize this identity key pair.
   */
  serialize(): Uint8Array {
    const n = getNative();
    return n.IdentityKeyPair_Serialize(
      this.publicKey._nativeHandle,
      this.privateKey._nativeHandle
    );
  }

  /**
   * Sign an alternate identity with this key pair.
   */
  signAlternateIdentity(other: PublicKey): Uint8Array {
    const n = getNative();
    return n.IdentityKeyPair_SignAlternateIdentity(
      this.publicKey._nativeHandle,
      this.privateKey._nativeHandle,
      other._nativeHandle
    );
  }
}

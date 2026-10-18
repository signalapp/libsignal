//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import * as Native from './Native.js';

export class PublicKey {
  readonly _nativeHandle: Native.PublicKey;

  private constructor(handle: Native.PublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  static deserialize(buf: Bytes): PublicKey {
    return new PublicKey(Native.PublicKey_Deserialize(buf));
  }

  equals(other: PublicKey): boolean {
    return Native.PublicKey_Equals(this, other);
  }

  serialize(): Bytes {
    return Native.PublicKey_Serialize(this);
  }

  getPublicKeyBytes(): Bytes {
    return Native.PublicKey_GetPublicKeyBytes(this);
  }

  verify(msg: Bytes, sig: Bytes): boolean {
    return Native.PublicKey_Verify(this, msg, sig);
  }

  verifyAlternateIdentity(other: PublicKey, signature: Bytes): boolean {
    return Native.IdentityKey_VerifyAlternateIdentity(this, other, signature);
  }

  /**
   * Seals a message so only the holder of the private key can decrypt it.
   *
   * Uses HPKE ({@link https://www.rfc-editor.org/rfc/rfc9180.html|RFC 9180}). The output will
   * include a type byte indicating the chosen algorithms and ciphertext layout. The `info`
   * parameter should typically be a static value describing the purpose of the message, while
   * `associatedData` can be used to restrict successful decryption beyond holding the private key.
   *
   * A string `info` will be encoded as UTF-8.
   *
   * @see PrivateKey#open
   */
  seal(msg: Bytes, info: string | Bytes, associatedData?: Bytes): Bytes {
    const infoBuffer =
      typeof info === 'string' ? new TextEncoder().encode(info) : info;
    return Native.PublicKey_HpkeSeal(
      this,
      msg,
      infoBuffer,
      associatedData ?? new Uint8Array()
    );
  }
}

export class PrivateKey {
  readonly _nativeHandle: Native.PrivateKey;

  private constructor(handle: Native.PrivateKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.PrivateKey): PrivateKey {
    return new PrivateKey(handle);
  }

  static generate(): PrivateKey {
    return new PrivateKey(Native.PrivateKey_Generate());
  }

  static deserialize(buf: Bytes): PrivateKey {
    return new PrivateKey(Native.PrivateKey_Deserialize(buf));
  }

  serialize(): Bytes {
    return Native.PrivateKey_Serialize(this);
  }

  sign(msg: Bytes): Bytes {
    return Native.PrivateKey_Sign(this, msg);
  }

  agree(other_key: PublicKey): Bytes {
    return Native.PrivateKey_Agree(this, other_key);
  }

  getPublicKey(): PublicKey {
    return PublicKey._fromNativeHandle(Native.PrivateKey_GetPublicKey(this));
  }

  /**
   * Opens a ciphertext sealed with {@link PublicKey#seal}.
   *
   * Uses HPKE ({@link https://www.rfc-editor.org/rfc/rfc9180.html|RFC 9180}). The input should
   * include its original type byte indicating the chosen algorithms and ciphertext layout. The
   * `info` and `associatedData` must match those used during sealing.
   */
  open(ciphertext: Bytes, info: string | Bytes, associatedData?: Bytes): Bytes {
    const infoBuffer =
      typeof info === 'string' ? new TextEncoder().encode(info) : info;
    return Native.PrivateKey_HpkeOpen(
      this,
      ciphertext,
      infoBuffer,
      associatedData ?? new Uint8Array()
    );
  }
}

export class IdentityKeyPair {
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;

  constructor(publicKey: PublicKey, privateKey: PrivateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  static generate(): IdentityKeyPair {
    const privateKey = PrivateKey.generate();
    return new IdentityKeyPair(privateKey.getPublicKey(), privateKey);
  }

  static deserialize(buffer: Bytes): IdentityKeyPair {
    const [publicKey, privateKey] = Native.IdentityKeyPair_Deserialize(buffer);
    return new IdentityKeyPair(
      PublicKey._fromNativeHandle(publicKey),
      PrivateKey._fromNativeHandle(privateKey)
    );
  }

  serialize(): Bytes {
    return Native.IdentityKeyPair_Serialize(this.publicKey, this.privateKey);
  }

  signAlternateIdentity(other: PublicKey): Bytes {
    return Native.IdentityKeyPair_SignAlternateIdentity(
      this.publicKey,
      this.privateKey,
      other
    );
  }
}

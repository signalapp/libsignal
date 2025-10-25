//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native.js';

export class PublicKey {
  readonly _nativeHandle: Native.PublicKey;

  private constructor(handle: Native.PublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(handle: Native.PublicKey): PublicKey {
    return new PublicKey(handle);
  }

  static deserialize(buf: Uint8Array): PublicKey {
    return new PublicKey(Native.PublicKey_Deserialize(buf));
  }

  /// Returns -1, 0, or 1
  compare(other: PublicKey): number {
    return Native.PublicKey_Compare(this, other);
  }

  serialize(): Uint8Array {
    return Native.PublicKey_Serialize(this);
  }

  getPublicKeyBytes(): Uint8Array {
    return Native.PublicKey_GetPublicKeyBytes(this);
  }

  verify(msg: Uint8Array, sig: Uint8Array): boolean {
    return Native.PublicKey_Verify(this, msg, sig);
  }

  verifyAlternateIdentity(other: PublicKey, signature: Uint8Array): boolean {
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
  seal(
    msg: Uint8Array,
    info: string | Uint8Array,
    associatedData?: Uint8Array
  ): Uint8Array {
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

  static deserialize(buf: Uint8Array): PrivateKey {
    return new PrivateKey(Native.PrivateKey_Deserialize(buf));
  }

  serialize(): Uint8Array {
    return Native.PrivateKey_Serialize(this);
  }

  sign(msg: Uint8Array): Uint8Array {
    return Native.PrivateKey_Sign(this, msg);
  }

  agree(other_key: PublicKey): Uint8Array {
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
  open(
    ciphertext: Uint8Array,
    info: string | Uint8Array,
    associatedData?: Uint8Array
  ): Uint8Array {
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

  static deserialize(buffer: Uint8Array): IdentityKeyPair {
    const [publicKey, privateKey] = Native.IdentityKeyPair_Deserialize(buffer);
    return new IdentityKeyPair(
      PublicKey._fromNativeHandle(publicKey),
      PrivateKey._fromNativeHandle(privateKey)
    );
  }

  serialize(): Uint8Array {
    return Native.IdentityKeyPair_Serialize(this.publicKey, this.privateKey);
  }

  signAlternateIdentity(other: PublicKey): Uint8Array {
    return Native.IdentityKeyPair_SignAlternateIdentity(
      this.publicKey,
      this.privateKey,
      other
    );
  }
}

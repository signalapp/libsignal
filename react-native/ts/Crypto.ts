//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native';

function getNative(): any {
  return (globalThis as any).__libsignal_native;
}

/**
 * AES-256-GCM-SIV authenticated encryption cipher.
 *
 * Provides nonce-misuse-resistant authenticated encryption.
 */
export class Aes256GcmSiv {
  readonly _nativeHandle: Native.Aes256GcmSiv;

  private constructor(handle: Native.Aes256GcmSiv) {
    this._nativeHandle = handle;
  }

  /**
   * Create a new AES-256-GCM-SIV cipher with the given 32-byte key.
   */
  static new(key: Uint8Array): Aes256GcmSiv {
    const n = getNative();
    return new Aes256GcmSiv(n.Aes256GcmSiv_New(key));
  }

  /**
   * Encrypt a plaintext with the given 12-byte nonce and optional associated data.
   * Returns ciphertext with authentication tag appended.
   */
  encrypt(
    plaintext: Uint8Array,
    nonce: Uint8Array,
    associatedData: Uint8Array = new Uint8Array(0)
  ): Uint8Array {
    const n = getNative();
    return n.Aes256GcmSiv_Encrypt(
      this._nativeHandle,
      plaintext,
      nonce,
      associatedData
    );
  }

  /**
   * Decrypt a ciphertext (with authentication tag) using the given nonce and associated data.
   * Throws if authentication fails.
   */
  decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    associatedData: Uint8Array = new Uint8Array(0)
  ): Uint8Array {
    const n = getNative();
    return n.Aes256GcmSiv_Decrypt(
      this._nativeHandle,
      ciphertext,
      nonce,
      associatedData
    );
  }
}

/**
 * Derive secrets using HKDF (RFC 5869).
 *
 * @param outputLength Number of bytes to derive
 * @param inputKeyMaterial Input key material
 * @param info Context and application-specific information
 * @param salt Optional salt value
 * @returns Derived key material
 */
export function hkdf(
  outputLength: number,
  inputKeyMaterial: Uint8Array,
  info: Uint8Array,
  salt: Uint8Array = new Uint8Array(0)
): Uint8Array {
  const n = getNative();
  const output = new Uint8Array(outputLength);
  n.Hkdf_Derive(output, inputKeyMaterial, info, salt);
  return output;
}

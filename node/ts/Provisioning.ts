//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * Encryption and decryption of the messages a primary device sends to provision (link) a secondary
 * device.
 *
 * @module Provisioning
 */

import type { Bytes } from '@signalapp/types';

import type { InvalidProvisioningMessageError } from './Errors.js';
import * as Native from './Native.js';
import * as NativeNice from './NativeNice.js';

/**
 * The state that a secondary device keeps while it is waiting to receive an encrypted `ProvisionMessage` or
 * `RegistrationProvisionMessage` from the primary.
 */
export class RecvProvisionCiphertextState {
  readonly _nativeHandle: Native.RecvProvisionCiphertextState;

  private constructor(handle: Native.RecvProvisionCiphertextState) {
    this._nativeHandle = handle;
  }

  /**
   * Generates a new state with a fresh, random keypair.
   */
  static generate(): RecvProvisionCiphertextState {
    return new RecvProvisionCiphertextState(
      Native.RecvProvisionCiphertextState_Generate()
    );
  }

  /**
   * The 33-byte serialized public key that the primary should encrypt to. This is what the
   * secondary puts in its provisioning QR code.
   */
  get publicKey(): Bytes {
    return NativeNice.RecvProvisionCiphertextState_GetPublicKey({
      state: this,
    });
  }

  /**
   * Decrypts a serialized `ProvisionEnvelope` and returns the underlying serialized
   * `ProvisionMessage` or `RegistrationProvisionMessage`.
   *
   * @throws {InvalidProvisioningMessageError} if the envelope is malformed, was not encrypted to
   *   this state's public key, or has been tampered with
   */
  decryptEnvelope(envelope: Bytes): Bytes {
    return NativeNice.RecvProvisionCiphertextState_DecryptEnvelope({
      state: this,
      envelope,
    });
  }
}

/**
 * Encrypts a serialized `ProvisionMessage` or `RegistrationProvisionMessage` to a secondary device,
 * returning a serialized `ProvisionEnvelope`.
 *
 * `secondaryPublicKey` is the 33-byte public key from the secondary's provisioning QR code, i.e.
 * {@link RecvProvisionCiphertextState.publicKey}.
 *
 * @throws {TypeError} if `secondaryPublicKey` is not 33 bytes
 * @throws {InvalidProvisioningMessageError} if the first byte of `secondaryPublicKey` is not the
 *   X25519 key type byte (0x05)
 */
export function encryptProvisionMessage(
  secondaryPublicKey: Bytes,
  provisionMessage: Bytes
): Bytes {
  return NativeNice.Provisioning_EncryptProvisionMessage({
    secondaryPublicKey,
    provisionMessage,
  });
}

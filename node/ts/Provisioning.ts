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

import type {
  InvalidProvisioningMessageError,
  LibSignalErrorBase,
} from './Errors.js';
import * as Native from './Native.js';
import * as NativeNice from './NativeNice.js';

/**
 * The public key that a secondary device puts in its provisioning QR code, and that the primary
 * encrypts the `ProvisionMessage` or `RegistrationProvisionMessage` to.
 */
export class ProvisioningPublicKey {
  readonly _nativeHandle: Native.ProvisioningPublicKey;

  private constructor(handle: Native.ProvisioningPublicKey) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    handle: Native.ProvisioningPublicKey
  ): ProvisioningPublicKey {
    return new ProvisioningPublicKey(handle);
  }

  /**
   * Wraps a serialized provisioning public key, i.e. the output of
   * {@link ProvisioningPublicKey.serialize}. The public key is not validated until it is used.
   */
  static deserialize(pubkeyBytes: Bytes): ProvisioningPublicKey {
    return new ProvisioningPublicKey(
      Native.ProvisioningPublicKey_Deserialize(pubkeyBytes)
    );
  }

  /**
   * Returns the bytes this public key was created from.
   */
  serialize(): Bytes {
    return NativeNice.ProvisioningPublicKey_Serialize({ key: this });
  }
}

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
   * The public key that the primary should encrypt to. This is what the secondary puts in its
   * provisioning QR code.
   */
  get publicKey(): ProvisioningPublicKey {
    return ProvisioningPublicKey._fromNativeHandle(
      Native.RecvProvisionCiphertextState_GetPublicKey(this)
    );
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
 * `secondaryPublicKey` is the public key from the secondary's provisioning QR code, i.e.
 * {@link RecvProvisionCiphertextState.publicKey}.
 *
 * @throws {LibSignalErrorBase} with the generic error code if `secondaryPublicKey` is malformed,
 *   as for other invalid keys
 */
export function encryptProvisionMessage(
  secondaryPublicKey: ProvisioningPublicKey,
  provisionMessage: Bytes
): Bytes {
  return NativeNice.Provisioning_EncryptProvisionMessage({
    secondaryPublicKey,
    provisionMessage,
  });
}

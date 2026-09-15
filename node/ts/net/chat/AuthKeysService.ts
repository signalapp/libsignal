//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { StandardNetworkError } from '../../Errors.js';
import type { PublicKey } from '../../EcKeys.js';
import type { ServiceIdKind } from '../../Address.js';
import type { KEMPublicKey } from '../../KemKeys.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthKeysService {}
}

export type PreKeyCounts = {
  /**
   * The approximate number of one-time EC pre-keys stored for the
   * authenticated device and associated with the caller's ACI.
   */
  aciEcPreKeyCount: number;
  /**
   * The approximate number of one-time KEM pre-keys stored for the
   * authenticated device and associated with the caller's ACI.
   */
  aciKemPreKeyCount: number;
  /**
   * The approximate number of one-time EC pre-keys stored for the
   * authenticated device and associated with the caller's PNI.
   */
  pniEcPreKeyCount: number;
  /**
   * The approximate number of one-time KEM pre-keys stored for the
   * authenticated device and associated with the caller's PNI.
   */
  pniKemPreKeyCount: number;
};

/**
 * A one-time elliptic-curve pre-key, as uploaded to the server.
 *
 * This is only the public half of the key; the private half never leaves the
 * device.
 */
export type PublicEcPreKey = {
  /**
   * A locally-unique identifier for this key, which peers using this key to
   * encrypt messages will provide so the private key can be looked up.
   *
   * Must be non-negative and less than `1 << 31`.
   */
  keyId: number;
  /**
   * The public key.
   */
  publicKey: PublicKey;
};

/**
 * A one-time KEM pre-key, as uploaded to the server.
 *
 * This is only the public half of the key; the private half never leaves the
 * device.
 */
export type PublicKemPreKey = {
  /**
   * A locally-unique identifier for this key, which peers using this key to
   * encrypt messages will provide so the private key can be looked up.
   *
   * Must be non-negative and less than `1 << 31`.
   */
  keyId: number;
  /**
   * The public key.
   */
  publicKey: KEMPublicKey;
  /**
   * The signature of the public key by the appropriate identity key.
   */
  signature: Uint8Array<ArrayBuffer>;
};

export interface AuthKeysService {
  /**
   * Retrieves an approximate count of the number of the various kinds of
   * one-time pre-keys stored for the authenticated device.
   *
   * @throws {StandardNetworkError}
   */
  getPreKeyCount: (options?: RequestOptions) => Promise<PreKeyCounts>;

  /**
   * Uploads a new set of one-time EC pre-keys for the authenticated device,
   * clearing any previously-stored one-time EC pre-keys for `identity`.
   *
   * `preKeys` must contain between 1 and 100 keys.
   *
   * @throws {StandardNetworkError}
   */
  setOneTimeEcPreKeys: (
    request: {
      identity: ServiceIdKind;
      preKeys: ReadonlyArray<PublicEcPreKey>;
    },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Uploads a new set of one-time KEM pre-keys for the authenticated device,
   * clearing any previously-stored one-time EC pre-keys for `identity`.
   *
   * `preKeys` must contain between 1 and 100 keys.
   *
   * @throws {StandardNetworkError}
   */
  setOneTimeKemPreKeys: (
    request: {
      identity: ServiceIdKind;
      preKeys: ReadonlyArray<PublicKemPreKey>;
    },
    options?: RequestOptions
  ) => Promise<void>;
}

AuthenticatedChatConnection.prototype.getPreKeyCount = async function (
  options?: RequestOptions
): Promise<PreKeyCounts> {
  return await NativeNice.AuthenticatedChatConnection_get_pre_key_count({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

AuthenticatedChatConnection.prototype.setOneTimeEcPreKeys = async function (
  { identity, preKeys },
  options?: RequestOptions
): Promise<void> {
  const ids = new Uint32Array(preKeys.length);
  const keys = new Array<PublicKey>(preKeys.length);
  preKeys.forEach((next, i) => {
    ids[i] = next.keyId;
    keys[i] = next.publicKey;
  });

  return await NativeNice.AuthenticatedChatConnection_set_one_time_ec_pre_keys({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    identityType: identity,
    preKeyIds: ids,
    preKeyData: keys,
  });
};

AuthenticatedChatConnection.prototype.setOneTimeKemPreKeys = async function (
  { identity, preKeys },
  options?: RequestOptions
): Promise<void> {
  const ids = new Uint32Array(preKeys.length);
  const keys = new Array<KEMPublicKey>(preKeys.length);
  const signatures = new Array<Uint8Array<ArrayBuffer>>(preKeys.length);
  preKeys.forEach((next, i) => {
    ids[i] = next.keyId;
    keys[i] = next.publicKey;
    signatures[i] = next.signature;
  });

  return await NativeNice.AuthenticatedChatConnection_set_one_time_kem_pre_keys(
    {
      asyncContext: this.asyncContext,
      abortSignal: options?.abortSignal,
      chat: this.chatService,
      identityType: identity,
      preKeyIds: ids,
      preKeyData: keys,
      preKeySignatures: signatures,
    }
  );
};

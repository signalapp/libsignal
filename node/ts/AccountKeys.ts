//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * Cryptographic hashing, randomness generation, etc. related to SVR/Backup Keys.
 *
 * @module AccountKeys
 */

import * as crypto from 'node:crypto';
import * as Native from './Native.js';
import ByteArray from './zkgroup/internal/ByteArray.js';
import { Aci } from './Address.js';
import { PrivateKey } from './EcKeys.js';

/**
 * The randomly-generated user-memorized entropy used to derive the backup key,
 *    with other possible future uses.
 *
 * Contains log_2(36^64) = ~330 bits of entropy.
 */
export class AccountEntropyPool {
  /**
   * Randomly generates an Account Entropy Pool and returns the canonical string
   *  representation of that pool.
   *
   * @returns cryptographically random 64 character string of characters a-z, 0-9
   */
  public static generate(): string {
    return Native.AccountEntropyPool_Generate();
  }

  /**
   * Checks whether a string can be used as an account entropy pool.
   *
   * @returns `true` if the string is a structurally valid account entropy value.
   */
  public static isValid(accountEntropyPool: string): boolean {
    return Native.AccountEntropyPool_IsValid(accountEntropyPool);
  }

  /**
   * Derives an SVR key from the given account entropy pool.
   *
   * `accountEntropyPool` must be a **validated** account entropy pool;
   * passing an arbitrary string here is considered a programmer error.
   */
  public static deriveSvrKey(
    accountEntropyPool: string
  ): Uint8Array<ArrayBuffer> {
    return Native.AccountEntropyPool_DeriveSvrKey(accountEntropyPool);
  }

  /**
   * Derives a backup key from the given account entropy pool.
   *
   * `accountEntropyPool` must be a **validated** account entropy pool;
   * passing an arbitrary string here is considered a programmer error.
   *
   * @see {@link BackupKey.generateRandom}
   */
  public static deriveBackupKey(accountEntropyPool: string): BackupKey {
    return new BackupKey(
      Native.AccountEntropyPool_DeriveBackupKey(accountEntropyPool)
    );
  }
}

/**
 * A key used for many aspects of backups.
 *
 * Clients are typically concerned with two long-lived keys: a "messages" key (sometimes called "the
 * root backup key" or just "the backup key") that's derived from an {@link AccountEntropyPool}, and
 * a "media" key (formally the "media root backup key") that's not derived from anything else.
 */
export class BackupKey extends ByteArray {
  private readonly __type?: never;
  static SIZE = 32;

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, BackupKey.checkLength(BackupKey.SIZE));
  }

  /**
   * Generates a random backup key.
   *
   * Useful for tests and for the media root backup key, which is not derived from anything else.
   *
   * @see {@link AccountEntropyPool.deriveBackupKey}
   */
  public static generateRandom(): BackupKey {
    const bytes = crypto.randomBytes(BackupKey.SIZE);
    return new BackupKey(bytes);
  }

  /**
   * Derives the backup ID to use given the current device's ACI.
   *
   * Used for both message and media backups.
   */
  public deriveBackupId(aci: Aci): Uint8Array<ArrayBuffer> {
    return Native.BackupKey_DeriveBackupId(
      this.contents,
      aci.getServiceIdFixedWidthBinary()
    );
  }

  /**
   * Derives the backup EC key to use given the current device's ACI.
   *
   * Used for both message and media backups.
   */
  public deriveEcKey(aci: Aci): PrivateKey {
    return PrivateKey._fromNativeHandle(
      Native.BackupKey_DeriveEcKey(
        this.contents,
        aci.getServiceIdFixedWidthBinary()
      )
    );
  }

  /**
   * Derives the AES key used for encrypted fields in local backup metadata.
   *
   * Only relevant for message backup keys.
   */
  public deriveLocalBackupMetadataKey(): Uint8Array<ArrayBuffer> {
    return Native.BackupKey_DeriveLocalBackupMetadataKey(this.contents);
  }

  /**
   * Derives the ID for uploading media with the name `mediaName`.
   *
   * Only relevant for media backup keys.
   */
  public deriveMediaId(mediaName: string): Uint8Array<ArrayBuffer> {
    return Native.BackupKey_DeriveMediaId(this.contents, mediaName);
  }

  /**
   * Derives the composite encryption key for re-encrypting media with the given ID.
   *
   * This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
   *
   * Only relevant for media backup keys.
   */
  public deriveMediaEncryptionKey(
    mediaId: Uint8Array<ArrayBuffer>
  ): Uint8Array<ArrayBuffer> {
    return Native.BackupKey_DeriveMediaEncryptionKey(this.contents, mediaId);
  }

  /**
   * Derives the composite encryption key for uploading thumbnails with the given ID to the "transit
   * tier" CDN.
   *
   * This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
   *
   * Only relevant for media backup keys.
   */
  public deriveThumbnailTransitEncryptionKey(
    mediaId: Uint8Array<ArrayBuffer>
  ): Uint8Array<ArrayBuffer> {
    return Native.BackupKey_DeriveThumbnailTransitEncryptionKey(
      this.contents,
      mediaId
    );
  }
}

/**
 * A hash of the pin that can be used to interact with a Secure Value Recovery service.
 *
 * Holds an opaque native handle. Use {@link PinHash.fromSalt} or
 * {@link PinHash.fromUsernameMrenclave} to construct.
 */
export class PinHash {
  readonly _nativeHandle: Native.PinHash;

  private constructor(nativeHandle: Native.PinHash) {
    this._nativeHandle = nativeHandle;
  }

  /**
   * Hash a pin using an explicit salt.
   *
   * @param normalizedPin A normalized, UTF-8 encoded byte representation of the pin
   * @param salt A 32 byte salt
   */
  static fromSalt(
    normalizedPin: Uint8Array<ArrayBuffer>,
    salt: Uint8Array<ArrayBuffer>
  ): PinHash {
    return new PinHash(Native.PinHash_FromSalt(normalizedPin, salt));
  }

  /**
   * Hash a pin for use with SVR2, deriving the salt from the username and mrenclave.
   *
   * @param normalizedPin A normalized, UTF-8 encoded byte representation of the pin
   * @param username The Basic Auth username used to authenticate with SVR2
   * @param mrenclave The mrenclave where the hashed pin will be stored
   */
  static fromUsernameMrenclave(
    normalizedPin: Uint8Array<ArrayBuffer>,
    username: string,
    mrenclave: Uint8Array<ArrayBuffer>
  ): PinHash {
    return new PinHash(
      Native.PinHash_FromUsernameMrenclave(normalizedPin, username, mrenclave)
    );
  }

  /** A 32 byte encryption key that can be used to encrypt or decrypt values before uploading them to a secure store. */
  get encryptionKey(): Uint8Array<ArrayBuffer> {
    return Native.PinHash_EncryptionKey(this);
  }

  /** A 32 byte secret that can be used to access a value in a secure store. */
  get accessKey(): Uint8Array<ArrayBuffer> {
    return Native.PinHash_AccessKey(this);
  }
}

/**
 * Supports operations on pins for Secure Value Recovery.
 *
 * Provides hashing pins for local verification and for use with the remote SVR
 * service. In either case, all pins are UTF-8 encoded bytes that must be
 * normalized *before* being provided. Normalizing a string pin requires the
 * following steps:
 *
 *  1. The string should be trimmed for leading and trailing whitespace.
 *  2. If the whole string consists of digits, then non-arabic digits must be replaced with their
 *     arabic 0-9 equivalents.
 *  3. The string must then be NKFD normalized.
 */
export const Pin = {
  /**
   * Create an encoded password hash string for local pin verification only.
   *
   * @param normalizedPin A normalized, UTF-8 encoded byte representation of the pin
   * @returns A hashed pin string that can be verified later
   */
  localHash(normalizedPin: Uint8Array<ArrayBuffer>): string {
    return Native.Pin_LocalHash(normalizedPin);
  },

  /**
   * Verify an encoded password hash against a pin.
   *
   * @param encodedHash An encoded string of the hash, as returned by {@link Pin.localHash}
   * @param normalizedPin A normalized, UTF-8 encoded byte representation of the pin to verify
   * @returns true if the pin matches the hash, false otherwise
   */
  verifyLocalHash(
    encodedHash: string,
    normalizedPin: Uint8Array<ArrayBuffer>
  ): boolean {
    return Native.Pin_VerifyLocalHash(encodedHash, normalizedPin);
  },
};

/**
 * A forward secrecy token used for deriving message backup keys.
 *
 * This token is retrieved from the server when restoring a backup and is used together
 * with the backup key to derive the actual encryption keys for message backups.
 */
export class BackupForwardSecrecyToken extends ByteArray {
  private readonly __type?: never;
  static SIZE = 32;

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(
      contents,
      BackupForwardSecrecyToken.checkLength(BackupForwardSecrecyToken.SIZE)
    );
  }
}

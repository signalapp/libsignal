//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * Cryptographic hashing, randomness generation, etc. related to SVR/Backup Keys.
 *
 * Currently only the Account Entropy Pool is exposed, because no other functionality is used on Desktop.
 *
 * @module AccountKeys
 */

import * as crypto from 'node:crypto';
import * as Native from '../Native';
import ByteArray from './zkgroup/internal/ByteArray';
import { Aci } from './Address';
import { PrivateKey } from './EcKeys';

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
  public static deriveSvrKey(accountEntropyPool: string): Buffer {
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

  constructor(contents: Buffer) {
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
  public deriveBackupId(aci: Aci): Buffer {
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
  public deriveLocalBackupMetadataKey(): Buffer {
    return Native.BackupKey_DeriveLocalBackupMetadataKey(this.contents);
  }

  /**
   * Derives the ID for uploading media with the name `mediaName`.
   *
   * Only relevant for media backup keys.
   */
  public deriveMediaId(mediaName: string): Buffer {
    return Native.BackupKey_DeriveMediaId(this.contents, mediaName);
  }

  /**
   * Derives the composite encryption key for re-encrypting media with the given ID.
   *
   * This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
   *
   * Only relevant for media backup keys.
   */
  public deriveMediaEncryptionKey(mediaId: Buffer): Buffer {
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
  public deriveThumbnailTransitEncryptionKey(mediaId: Buffer): Buffer {
    return Native.BackupKey_DeriveThumbnailTransitEncryptionKey(
      this.contents,
      mediaId
    );
  }
}

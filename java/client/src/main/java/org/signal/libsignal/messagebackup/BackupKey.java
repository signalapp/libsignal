//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.security.SecureRandom;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/**
 * A key used for many aspects of backups.
 *
 * <p>Clients are typically concerned with two long-lived keys: a "messages" key (sometimes called
 * "the root backup key" or just "the backup key") that's derived from an {@link
 * AccountEntropyPool}, and a "media" key (formally the "media root backup key") that's not derived
 * from anything else.
 */
public class BackupKey extends ByteArray {
  public static final int SIZE = 32;

  public BackupKey(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }

  /**
   * Generates a random backup key.
   *
   * <p>Useful for tests and for the media root backup key, which is not derived from anything else.
   *
   * @see AccountEntropyPool#deriveBackupKey
   */
  public static BackupKey generateRandom() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] bytes = new byte[BackupKey.SIZE];
    secureRandom.nextBytes(bytes);
    return filterExceptions(() -> new BackupKey(bytes));
  }

  /**
   * Derives the backup ID to use given the current device's ACI.
   *
   * <p>Used for both messages and media backups.
   */
  public byte[] deriveBackupId(Aci aci) {
    return Native.BackupKey_DeriveBackupId(
        this.getInternalContentsForJNI(), aci.toServiceIdFixedWidthBinary());
  }

  /**
   * Derives the backup EC key to use given the current device's ACI.
   *
   * <p>Used for both messages and media backups.
   */
  public ECPrivateKey deriveEcKey(Aci aci) {
    return new ECPrivateKey(
        Native.BackupKey_DeriveEcKey(
            this.getInternalContentsForJNI(), aci.toServiceIdFixedWidthBinary()));
  }

  /**
   * Derives the AES key used for encrypted fields in local backup metadata.
   *
   * <p>Only relevant for message backup keys.
   */
  public byte[] deriveLocalBackupMetadataKey() {
    return Native.BackupKey_DeriveLocalBackupMetadataKey(this.getInternalContentsForJNI());
  }

  /**
   * Derives the ID for uploading media with the name {@code mediaName}.
   *
   * <p>Only relevant for media backup keys.
   */
  public byte[] deriveMediaId(String mediaName) {
    return Native.BackupKey_DeriveMediaId(this.getInternalContentsForJNI(), mediaName);
  }

  /**
   * Derives the composite encryption key for re-encrypting media with the given ID.
   *
   * <p>This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
   *
   * <p>Only relevant for media backup keys.
   *
   * <p>Throws {@link IllegalArgumentException} if the media ID is invalid.
   */
  public byte[] deriveMediaEncryptionKey(byte[] mediaId) {
    return Native.BackupKey_DeriveMediaEncryptionKey(this.getInternalContentsForJNI(), mediaId);
  }

  /**
   * Derives the composite encryption key for uploading thumbnails with the given ID to the "transit
   * tier" CDN.
   *
   * <p>This is a concatenation of an HMAC key (32 bytes) and an AES-CBC key (also 32 bytes).
   *
   * <p>Only relevant for media backup keys.
   *
   * <p>Throws {@link IllegalArgumentException} if the media ID is invalid.
   */
  public byte[] deriveThumbnailTransitEncryptionKey(byte[] mediaId) {
    return Native.BackupKey_DeriveThumbnailTransitEncryptionKey(
        this.getInternalContentsForJNI(), mediaId);
  }
}

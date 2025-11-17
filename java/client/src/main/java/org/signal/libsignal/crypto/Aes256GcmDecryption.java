//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

/**
 * Implements the <a
 * href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Galois/counter_(GCM)">AES-256-GCM</a>
 * authenticated stream cipher with a 12-byte nonce.
 *
 * <p>This API exposes the streaming nature of AES-GCM to allow decrypting data without having it
 * resident in memory all at once. You <strong>must</strong> call {@link #verifyTag} when the
 * decryption is complete, or else you have no authenticity guarantees.
 *
 * @see Aes256GcmEncryption
 */
public class Aes256GcmDecryption extends NativeHandleGuard.SimpleOwner {
  /** The size of the authentication tag, as used by {@link #verifyTag} */
  public static final int TAG_SIZE_IN_BYTES = 16;

  /**
   * Initializes the cipher with the given inputs.
   *
   * <p>The associated data is not included in the plaintext or tag; instead, it's expected to match
   * between the encrypter and decrypter.
   */
  public Aes256GcmDecryption(byte[] key, byte[] nonce, byte[] associatedData)
      throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class,
            () -> Native.Aes256GcmDecryption_New(key, nonce, associatedData)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.Aes256GcmDecryption_Destroy(nativeHandle);
  }

  /**
   * Decrypts {@code ciphertext} in place and advances the state of the cipher.
   *
   * <p>Don't forget to call {@link #verifyTag} when decryption is complete.
   */
  public void decrypt(byte[] ciphertext) {
    guardedRun(
        (nativeHandle) ->
            Native.Aes256GcmDecryption_Update(nativeHandle, ciphertext, 0, ciphertext.length));
  }

  /**
   * Decrypts {@code ciphertext} in place and advances the state of the cipher.
   *
   * <p>Bytes outside the designated offset/length are unchanged.
   *
   * <p>Don't forget to call {@link #verifyTag} when decryption is complete.
   */
  public void decrypt(byte[] ciphertext, int offset, int length) {
    guardedRun(
        (nativeHandle) ->
            Native.Aes256GcmDecryption_Update(nativeHandle, ciphertext, offset, length));
  }

  /**
   * Returns {@code true} if and only if {@code tag} matches the ciphertext that has been processed.
   *
   * <p>After calling {@code verifyTag}, this object may not be used anymore.
   */
  public boolean verifyTag(byte[] tag) {
    return guardedMap(
        (nativeHandle) ->
            filterExceptions(() -> Native.Aes256GcmDecryption_VerifyTag(nativeHandle, tag)));
  }
}

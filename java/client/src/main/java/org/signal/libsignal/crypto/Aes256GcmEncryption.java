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
 * <p>This API exposes the streaming nature of AES-GCM to allow encrypting data without having it
 * resident in memory all at once. You must call {@link #computeTag} when the encryption is complete
 * to produce the authentication tag for the ciphertext, and then make sure the tag makes it to the
 * decrypter.
 *
 * @see Aes256GcmDecryption
 */
public class Aes256GcmEncryption extends NativeHandleGuard.SimpleOwner {
  /**
   * Initializes the cipher with the given inputs.
   *
   * <p>The associated data is not included in the plaintext or tag; instead, it's expected to match
   * between the encrypter and decrypter. If you don't need any extra data, pass an empty array.
   */
  public Aes256GcmEncryption(byte[] key, byte[] nonce, byte[] associatedData)
      throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class,
            () -> Native.Aes256GcmEncryption_New(key, nonce, associatedData)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.Aes256GcmEncryption_Destroy(nativeHandle);
  }

  /**
   * Encrypts {@code plaintext} in place and advances the state of the cipher.
   *
   * <p>Bytes outside the designated offset/length are unchanged.
   *
   * <p>Don't forget to call {@link #computeTag} when encryption is complete.
   */
  public void encrypt(byte[] plaintext, int offset, int length) {
    guardedRun(
        (nativeHandle) ->
            Native.Aes256GcmEncryption_Update(nativeHandle, plaintext, offset, length));
  }

  /**
   * Encrypts {@code plaintext} in place and advances the state of the cipher.
   *
   * <p>Don't forget to call {@link #computeTag} when encryption is complete.
   */
  public void encrypt(byte[] plaintext) {
    guardedRun(
        (nativeHandle) ->
            Native.Aes256GcmEncryption_Update(nativeHandle, plaintext, 0, plaintext.length));
  }

  /**
   * Produces an authentication tag for the plaintext that has been processed.
   *
   * <p>After calling {@code computeTag}, this object may not be used anymore.
   */
  public byte[] computeTag() {
    return guardedMap(Native::Aes256GcmEncryption_ComputeTag);
  }
}

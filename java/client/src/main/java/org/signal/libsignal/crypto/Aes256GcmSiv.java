//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;

/**
 * Implements the <a href="https://en.wikipedia.org/wiki/AES-GCM-SIV">AES-256-GCM-SIV</a>
 * authenticated stream cipher with a 12-byte nonce.
 *
 * <p>AES-GCM-SIV is a multi-pass algorithm (to generate the "synthetic initialization vector"), so
 * this API does not expose a streaming form.
 */
public class Aes256GcmSiv extends NativeHandleGuard.SimpleOwner {

  public Aes256GcmSiv(byte[] key) throws InvalidKeyException {
    super(filterExceptions(InvalidKeyException.class, () -> Native.Aes256GcmSiv_New(key)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.Aes256GcmSiv_Destroy(nativeHandle);
  }

  /**
   * Encrypts the given plaintext using the given nonce, and authenticating the ciphertext and given
   * associated data.
   *
   * <p>The associated data is not included in the ciphertext; instead, it's expected to match
   * between the encrypter and decrypter. If you don't need any extra data, pass an empty array.
   *
   * @return The encrypted data, including an appended 16-byte authentication tag.
   */
  public byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] associated_data) {
    return filterExceptions(
        () ->
            guardedMapChecked(
                nativeHandle ->
                    Native.Aes256GcmSiv_Encrypt(nativeHandle, plaintext, nonce, associated_data)));
  }

  /**
   * Decrypts the given ciphertext using the given nonce, and authenticating the ciphertext and
   * given associated data.
   *
   * <p>The associated data is not included in the ciphertext; instead, it's expected to match
   * between the encrypter and decrypter.
   *
   * @return The decrypted data
   */
  public byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] associated_data)
      throws InvalidMessageException {
    return filterExceptions(
        InvalidMessageException.class,
        () ->
            guardedMapChecked(
                (nativeHandle) ->
                    Native.Aes256GcmSiv_Decrypt(nativeHandle, ciphertext, nonce, associated_data)));
  }
}

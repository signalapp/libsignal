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
 * href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)">AES-256-CTR</a>
 * stream cipher with a 12-byte nonce and an initial counter.
 *
 * <p>CTR mode is built on XOR, so encrypting and decrypting are the same operation.
 */
public class Aes256Ctr32 extends NativeHandleGuard.SimpleOwner {
  public Aes256Ctr32(byte[] key, byte[] nonce, int initialCtr) throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class, () -> Native.Aes256Ctr32_New(key, nonce, initialCtr)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.Aes256Ctr32_Destroy(nativeHandle);
  }

  /**
   * Encrypts the plaintext, or decrypts the ciphertext, in {@code data}, in place, advancing the
   * state of the cipher.
   */
  public void process(byte[] data) {
    this.process(data, 0, data.length);
  }

  /**
   * Encrypts the plaintext, or decrypts the ciphertext, in {@code data}, in place, advancing the
   * state of the cipher.
   *
   * <p>Bytes outside the designated offset/length are unchanged.
   */
  public void process(byte[] data, int offset, int length) {
    guardedRun((nativeHandle) -> Native.Aes256Ctr32_Process(nativeHandle, data, offset, length));
  }
}

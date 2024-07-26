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

public class Aes256GcmSiv implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public Aes256GcmSiv(byte[] key) throws InvalidKeyException {
    this.unsafeHandle =
        filterExceptions(InvalidKeyException.class, () -> Native.Aes256GcmSiv_New(key));
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.Aes256GcmSiv_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] associated_data) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () ->
              Native.Aes256GcmSiv_Encrypt(guard.nativeHandle(), plaintext, nonce, associated_data));
    }
  }

  public byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] associated_data)
      throws InvalidMessageException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          InvalidMessageException.class,
          () ->
              Native.Aes256GcmSiv_Decrypt(
                  guard.nativeHandle(), ciphertext, nonce, associated_data));
    }
  }
}

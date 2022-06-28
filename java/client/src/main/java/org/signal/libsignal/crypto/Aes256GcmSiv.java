//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidKeyException;

class Aes256GcmSiv implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public Aes256GcmSiv(byte[] key) throws InvalidKeyException {
    this.unsafeHandle = Native.Aes256GcmSiv_New(key);
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.Aes256GcmSiv_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] associated_data)
      throws InvalidMessageException, IllegalArgumentException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.Aes256GcmSiv_Encrypt(guard.nativeHandle(), plaintext, nonce, associated_data);
    }
  }

  byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] associated_data)
      throws InvalidMessageException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.Aes256GcmSiv_Decrypt(guard.nativeHandle(), ciphertext, nonce, associated_data);
    }
  }
}

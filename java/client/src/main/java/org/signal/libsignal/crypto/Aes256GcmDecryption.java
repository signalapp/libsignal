//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

public class Aes256GcmDecryption implements NativeHandleGuard.Owner {
  public static final int TAG_SIZE_IN_BYTES = 16;

  private long unsafeHandle;

  public Aes256GcmDecryption(byte[] key, byte[] nonce, byte[] associatedData) throws InvalidKeyException {
    this.unsafeHandle = Native.Aes256GcmDecryption_New(key, nonce, associatedData);
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.Aes256GcmDecryption_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public void decrypt(byte[] plaintext) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Aes256GcmDecryption_Update(guard.nativeHandle(), plaintext, 0, plaintext.length);
    }
  }

  public void decrypt(byte[] plaintext, int offset, int length) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Aes256GcmDecryption_Update(guard.nativeHandle(), plaintext, offset, length);
    }
  }

  public boolean verifyTag(byte[] tag) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      boolean tagOk = Native.Aes256GcmDecryption_VerifyTag(guard.nativeHandle(), tag);
      Native.Aes256GcmDecryption_Destroy(guard.nativeHandle());
      this.unsafeHandle = 0;
      return tagOk;
    }
  }

}

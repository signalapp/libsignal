//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;
import org.whispersystems.libsignal.InvalidKeyException;

public class Aes256GcmEncryption implements NativeHandleGuard.Owner {
  private long unsafeHandle;

  public Aes256GcmEncryption(byte[] key, byte[] nonce, byte[] associatedData) throws InvalidKeyException {
    this.unsafeHandle = Native.Aes256GcmEncryption_New(key, nonce, associatedData);
  }

  @Override
  protected void finalize() {
    Native.Aes256GcmEncryption_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public void encrypt(byte[] plaintext, int offset, int length) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Aes256GcmEncryption_Update(guard.nativeHandle(), plaintext, offset, length);
    }
  }

  public void encrypt(byte[] plaintext) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Aes256GcmEncryption_Update(guard.nativeHandle(), plaintext, 0, plaintext.length);
    }
  }

  public byte[] computeTag() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      byte[] tag = Native.Aes256GcmEncryption_ComputeTag(guard.nativeHandle());
      Native.Aes256GcmEncryption_Destroy(guard.nativeHandle());
      this.unsafeHandle = 0;
      return tag;
    }
  }

}

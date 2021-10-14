//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;
import org.whispersystems.libsignal.InvalidKeyException;

public class Aes256Ctr32 implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public Aes256Ctr32(byte[] key, byte[] nonce, int initialCtr) throws InvalidKeyException {
    this.unsafeHandle = Native.Aes256Ctr32_New(key, nonce, initialCtr);
  }

  @Override
  protected void finalize() {
    Native.Aes256Ctr32_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public void process(byte[] data) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Aes256Ctr32_Process(guard.nativeHandle(), data, 0, data.length);
    }
  }

  public void process(byte[] data, int offset, int length) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.Aes256Ctr32_Process(guard.nativeHandle(), data, offset, length);
    }
  }
}

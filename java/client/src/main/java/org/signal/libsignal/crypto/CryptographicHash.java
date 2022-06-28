//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class CryptographicHash implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public CryptographicHash(String algo) {
    this.unsafeHandle = Native.CryptographicHash_New(algo);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return unsafeHandle;
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.CryptographicHash_Destroy(this.unsafeHandle);
  }

  public void update(byte[] input, int offset, int len) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.CryptographicHash_UpdateWithOffset(guard.nativeHandle(), input, offset, len);
    }
  }

  public void update(byte[] input) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.CryptographicHash_Update(guard.nativeHandle(), input);
    }
  }

  public byte[] finish() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.CryptographicHash_Finalize(guard.nativeHandle());
    }
  }

}

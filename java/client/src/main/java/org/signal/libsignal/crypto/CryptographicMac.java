//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class CryptographicMac implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public CryptographicMac(String algo, byte[] key) {
    this.unsafeHandle = Native.CryptographicMac_New(algo, key);
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.CryptographicMac_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public void update(byte[] input, int offset, int len) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.CryptographicMac_UpdateWithOffset(guard.nativeHandle(), input, offset, len);
    }
  }

  public void update(byte[] input) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      Native.CryptographicMac_Update(guard.nativeHandle(), input);
    }
  }

  public byte[] finish() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.CryptographicMac_Finalize(guard.nativeHandle());
    }
  }

}

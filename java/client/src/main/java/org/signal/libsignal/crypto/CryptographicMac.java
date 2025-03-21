//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class CryptographicMac extends NativeHandleGuard.SimpleOwner {
  public CryptographicMac(String algo, byte[] key) {
    super(filterExceptions(() -> Native.CryptographicMac_New(algo, key)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.CryptographicMac_Destroy(nativeHandle);
  }

  public void update(byte[] input, int offset, int len) {
    guardedRun(
        (nativeHandle) ->
            Native.CryptographicMac_UpdateWithOffset(nativeHandle, input, offset, len));
  }

  public void update(byte[] input) {
    guardedRun((nativeHandle) -> Native.CryptographicMac_Update(nativeHandle, input));
  }

  public byte[] finish() {
    return guardedMap(Native::CryptographicMac_Finalize);
  }
}

//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class CryptographicHash extends NativeHandleGuard.SimpleOwner {
  public CryptographicHash(String algo) {
    super(filterExceptions(() -> Native.CryptographicHash_New(algo)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.CryptographicHash_Destroy(nativeHandle);
  }

  public void update(byte[] input, int offset, int len) {
    guardedRun(
        (nativeHandle) ->
            Native.CryptographicHash_UpdateWithOffset(nativeHandle, input, offset, len));
  }

  public void update(byte[] input) {
    guardedRun((nativeHandle) -> Native.CryptographicHash_Update(nativeHandle, input));
  }

  public byte[] finish() {
    return guardedMap(Native::CryptographicHash_Finalize);
  }
}

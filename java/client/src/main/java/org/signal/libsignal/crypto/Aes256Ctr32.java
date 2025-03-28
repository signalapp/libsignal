//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

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

  public void process(byte[] data) {
    this.process(data, 0, data.length);
  }

  public void process(byte[] data, int offset, int length) {
    guardedRun((nativeHandle) -> Native.Aes256Ctr32_Process(nativeHandle, data, offset, length));
  }
}

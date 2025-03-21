//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

public class KEMSecretKey extends NativeHandleGuard.SimpleOwner {
  public KEMSecretKey(byte[] privateKey) throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class, () -> Native.KyberSecretKey_Deserialize(privateKey)));
  }

  public KEMSecretKey(long nativeHandle) {
    super(KEMSecretKey.throwIfNull(nativeHandle));
  }

  private static long throwIfNull(long handle) {
    if (handle == 0) {
      throw new NullPointerException();
    }
    return handle;
  }

  @Override
  protected void release(long nativeHandle) {
    Native.KyberSecretKey_Destroy(nativeHandle);
  }

  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::KyberSecretKey_Serialize));
  }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

public class KEMSecretKey implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public KEMSecretKey(byte[] privateKey) throws InvalidKeyException {
    this.unsafeHandle = Native.KyberSecretKey_Deserialize(privateKey);
  }

  public KEMSecretKey(long nativeHandle) {
    if(nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.unsafeHandle = nativeHandle;
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
     Native.KyberSecretKey_Destroy(this.unsafeHandle);
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.KyberSecretKey_Serialize(guard.nativeHandle());
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}

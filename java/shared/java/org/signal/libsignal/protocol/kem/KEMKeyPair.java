//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.protocol.kem;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class KEMKeyPair implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  public static KEMKeyPair generate(KEMKeyType reserved) {
    // Presently only kyber 1024 is supported
    return new KEMKeyPair(Native.KyberKeyPair_Generate());
  }

  public KEMKeyPair(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.unsafeHandle = nativeHandle;
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
     Native.KyberKeyPair_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }


  public KEMPublicKey getPublicKey() {
    return new KEMPublicKey(Native.KyberKeyPair_GetPublicKey(this.unsafeHandle));
  }

  public KEMSecretKey getSecretKey() {
    return new KEMSecretKey(Native.KyberKeyPair_GetSecretKey(this.unsafeHandle));
  }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class KEMKeyPair extends NativeHandleGuard.SimpleOwner {
  public static KEMKeyPair generate(KEMKeyType reserved) {
    // Presently only kyber 1024 is supported
    return new KEMKeyPair(Native.KyberKeyPair_Generate());
  }

  public KEMKeyPair(long nativeHandle) {
    super(KEMKeyPair.throwIfNull(nativeHandle));
  }

  private static long throwIfNull(long handle) {
    if (handle == 0) {
      throw new NullPointerException();
    }
    return handle;
  }

  @Override
  protected void release(long nativeHandle) {
    Native.KyberKeyPair_Destroy(nativeHandle);
  }

  public KEMPublicKey getPublicKey() {
    return new KEMPublicKey(guardedMap(Native::KyberKeyPair_GetPublicKey));
  }

  public KEMSecretKey getSecretKey() {
    return new KEMSecretKey(guardedMap(Native::KyberKeyPair_GetSecretKey));
  }
}

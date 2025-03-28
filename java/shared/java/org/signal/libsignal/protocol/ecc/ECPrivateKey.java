//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ecc;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

public class ECPrivateKey extends NativeHandleGuard.SimpleOwner {
  static ECPrivateKey generate() {
    return new ECPrivateKey(Native.ECPrivateKey_Generate());
  }

  public ECPrivateKey(byte[] privateKey) throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class, () -> Native.ECPrivateKey_Deserialize(privateKey)));
  }

  public ECPrivateKey(long nativeHandle) {
    super(ECPrivateKey.throwIfNull(nativeHandle));
  }

  private static long throwIfNull(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    return nativeHandle;
  }

  @Override
  protected void release(long nativeHandle) {
    Native.ECPrivateKey_Destroy(nativeHandle);
  }

  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::ECPrivateKey_Serialize));
  }

  public byte[] calculateSignature(byte[] message) {
    return filterExceptions(
        () -> guardedMapChecked((nativeHandle) -> Native.ECPrivateKey_Sign(nativeHandle, message)));
  }

  public byte[] calculateAgreement(ECPublicKey other) {
    try (NativeHandleGuard privateKey = new NativeHandleGuard(this);
        NativeHandleGuard publicKey = new NativeHandleGuard(other); ) {
      return filterExceptions(
          () -> Native.ECPrivateKey_Agree(privateKey.nativeHandle(), publicKey.nativeHandle()));
    }
  }

  public ECPublicKey publicKey() {
    return new ECPublicKey(
        filterExceptions(() -> guardedMapChecked(Native::ECPrivateKey_GetPublicKey)));
  }
}

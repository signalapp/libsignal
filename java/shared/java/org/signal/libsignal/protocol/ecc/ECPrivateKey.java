//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ecc;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

public class ECPrivateKey implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  static ECPrivateKey generate() {
    return new ECPrivateKey(Native.ECPrivateKey_Generate());
  }

  public ECPrivateKey(byte[] privateKey) throws InvalidKeyException {
    this.unsafeHandle =
        filterExceptions(
            InvalidKeyException.class, () -> Native.ECPrivateKey_Deserialize(privateKey));
  }

  public ECPrivateKey(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.unsafeHandle = nativeHandle;
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.ECPrivateKey_Destroy(this.unsafeHandle);
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ECPrivateKey_Serialize(guard.nativeHandle()));
    }
  }

  public byte[] calculateSignature(byte[] message) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ECPrivateKey_Sign(guard.nativeHandle(), message));
    }
  }

  public byte[] calculateAgreement(ECPublicKey other) {
    try (NativeHandleGuard privateKey = new NativeHandleGuard(this);
        NativeHandleGuard publicKey = new NativeHandleGuard(other); ) {
      return filterExceptions(
          () -> Native.ECPrivateKey_Agree(privateKey.nativeHandle(), publicKey.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public ECPublicKey publicKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(
          filterExceptions(() -> Native.ECPrivateKey_GetPublicKey(guard.nativeHandle())));
    }
  }
}

//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ecc;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.Arrays;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

public class ECPublicKey extends NativeHandleGuard.SimpleOwner implements Comparable<ECPublicKey> {

  public static final int KEY_SIZE = 33;

  public ECPublicKey(byte[] serialized, int offset) throws InvalidKeyException {
    this(
        filterExceptions(
            InvalidKeyException.class, () -> Native.ECPublicKey_Deserialize(serialized, offset)));
  }

  public ECPublicKey(byte[] serialized) throws InvalidKeyException {
    this(
        filterExceptions(
            InvalidKeyException.class, () -> Native.ECPublicKey_Deserialize(serialized, 0)));
  }

  public static ECPublicKey fromPublicKeyBytes(byte[] key) throws InvalidKeyException {
    if (key.length != KEY_SIZE - 1) {
      throw new InvalidKeyException(
          "invalid number of public key bytes (expected "
              + (KEY_SIZE - 1)
              + ", was "
              + key.length
              + ")");
    }
    byte[] with_type = new byte[KEY_SIZE];
    with_type[0] = 0x05;
    System.arraycopy(key, 0, with_type, 1, KEY_SIZE - 1);
    return new ECPublicKey(filterExceptions(() -> Native.ECPublicKey_Deserialize(with_type, 0)));
  }

  public ECPublicKey(long nativeHandle) {
    super(nativeHandle);
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
  }

  @Override
  protected void release(long nativeHandle) {
    if (nativeHandle != 0) {
      Native.ECPublicKey_Destroy(nativeHandle);
    }
  }

  public boolean verifySignature(byte[] message, byte[] signature) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ECPublicKey_Verify(guard.nativeHandle(), message, signature);
    }
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ECPublicKey_Serialize(guard.nativeHandle()));
    }
  }

  public byte[] getPublicKeyBytes() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ECPublicKey_GetPublicKeyBytes(guard.nativeHandle()));
    }
  }

  public int getType() {
    byte[] serialized = this.serialize();
    return serialized[0];
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) return false;
    if (!(other instanceof ECPublicKey)) return false;
    try (NativeHandleGuard thisGuard = new NativeHandleGuard(this);
        NativeHandleGuard thatGuard = new NativeHandleGuard((ECPublicKey) other); ) {
      return Native.ECPublicKey_Equals(thisGuard.nativeHandle(), thatGuard.nativeHandle());
    }
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.serialize());
  }

  @Override
  public int compareTo(ECPublicKey another) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this);
        NativeHandleGuard otherGuard = new NativeHandleGuard(another); ) {
      return Native.ECPublicKey_Compare(guard.nativeHandle(), otherGuard.nativeHandle());
    }
  }
}

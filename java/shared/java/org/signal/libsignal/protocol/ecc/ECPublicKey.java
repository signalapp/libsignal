/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.signal.libsignal.protocol.ecc;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import java.util.Arrays;

public class ECPublicKey implements Comparable<ECPublicKey>, NativeHandleGuard.Owner {

  public static final int KEY_SIZE = 33;

  private final long unsafeHandle;

  public ECPublicKey(byte[] serialized, int offset) throws InvalidKeyException {
    this.unsafeHandle = Native.ECPublicKey_Deserialize(serialized, offset);
  }

  public ECPublicKey(byte[] serialized) throws InvalidKeyException {
    this.unsafeHandle = Native.ECPublicKey_Deserialize(serialized, 0);
  }

  static public ECPublicKey fromPublicKeyBytes(byte[] key) {
    byte[] with_type = new byte[33];
    with_type[0] = 0x05;
    System.arraycopy(key, 0, with_type, 1, 32);
    return new ECPublicKey(Native.ECPublicKey_Deserialize(with_type, 0));
  }

  public ECPublicKey(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.unsafeHandle = nativeHandle;
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
     Native.ECPublicKey_Destroy(this.unsafeHandle);
  }

  public boolean verifySignature(byte[] message, byte[] signature) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ECPublicKey_Verify(guard.nativeHandle(), message, signature);
    }
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ECPublicKey_Serialize(guard.nativeHandle());
    }
  }

  public byte[] getPublicKeyBytes() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ECPublicKey_GetPublicKeyBytes(guard.nativeHandle());
    }
  }

  public int getType() {
    byte[] serialized = this.serialize();
    return serialized[0];
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                   return false;
    if (!(other instanceof ECPublicKey)) return false;
    try (
      NativeHandleGuard thisGuard = new NativeHandleGuard(this);
      NativeHandleGuard thatGuard = new NativeHandleGuard((ECPublicKey)other);
    ) {
      return Native.ECPublicKey_Equals(thisGuard.nativeHandle(), thatGuard.nativeHandle());
    }
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.serialize());
  }

  @Override
  public int compareTo(ECPublicKey another) {
    try (
      NativeHandleGuard guard = new NativeHandleGuard(this);
      NativeHandleGuard otherGuard = new NativeHandleGuard(another);
    ) {
      return Native.ECPublicKey_Compare(guard.nativeHandle(), otherGuard.nativeHandle());
    }
  }
}

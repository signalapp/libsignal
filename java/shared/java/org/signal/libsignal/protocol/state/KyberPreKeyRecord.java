//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.protocol.state;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.kem.KEMKeyPair;

public class KyberPreKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.KyberPreKeyRecord_Destroy(this.unsafeHandle);
  }

  public KyberPreKeyRecord(int id, long timestamp, KEMKeyPair keyPair, byte[] signature) {
    try (
      NativeHandleGuard guard = new NativeHandleGuard(keyPair);
    ) {
      this.unsafeHandle = Native.KyberPreKeyRecord_New(
        id,
        timestamp,
        guard.nativeHandle(),
        signature);
    }
  }

  // FIXME: This shouldn't be considered a "message".
  public KyberPreKeyRecord(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle = Native.KyberPreKeyRecord_Deserialize(serialized);
  }

  public int getId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.KyberPreKeyRecord_GetId(guard.nativeHandle());
    }
  }

  public long getTimestamp() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.KyberPreKeyRecord_GetTimestamp(guard.nativeHandle());
    }
  }

  public KEMKeyPair getKeyPair() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new KEMKeyPair(Native.KyberPreKeyRecord_GetKeyPair(guard.nativeHandle()));
    }
  }

  public byte[] getSignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.KyberPreKeyRecord_GetSignature(guard.nativeHandle());
    }
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.KyberPreKeyRecord_GetSerialized(guard.nativeHandle());
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

}

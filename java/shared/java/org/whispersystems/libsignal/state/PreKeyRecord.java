/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.io.IOException;

public class PreKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  protected void finalize() {
    Native.PreKeyRecord_Destroy(this.unsafeHandle);
  }

  public PreKeyRecord(int id, ECKeyPair keyPair) {
    try (
      NativeHandleGuard publicKey = new NativeHandleGuard(keyPair.getPublicKey());
      NativeHandleGuard privateKey = new NativeHandleGuard(keyPair.getPrivateKey());
    ) {
      this.unsafeHandle = Native.PreKeyRecord_New(id, publicKey.nativeHandle(), privateKey.nativeHandle());
    }
  }

  public PreKeyRecord(byte[] serialized) throws IOException {
    this.unsafeHandle = Native.PreKeyRecord_Deserialize(serialized);
  }

  public int getId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyRecord_GetId(guard.nativeHandle());
    }
  }

  public ECKeyPair getKeyPair() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      ECPublicKey publicKey = new ECPublicKey(Native.PreKeyRecord_GetPublicKey(guard.nativeHandle()));
      ECPrivateKey privateKey = new ECPrivateKey(Native.PreKeyRecord_GetPrivateKey(guard.nativeHandle()));
      return new ECKeyPair(publicKey, privateKey);
    }
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyRecord_GetSerialized(guard.nativeHandle());
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}

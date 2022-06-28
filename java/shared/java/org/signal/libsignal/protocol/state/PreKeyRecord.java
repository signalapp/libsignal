/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.state;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public class PreKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override @SuppressWarnings("deprecation")
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

  // FIXME: This shouldn't be considered a "message".
  public PreKeyRecord(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle = Native.PreKeyRecord_Deserialize(serialized);
  }

  public int getId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyRecord_GetId(guard.nativeHandle());
    }
  }

  public ECKeyPair getKeyPair() throws InvalidKeyException {
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

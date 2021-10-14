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

public class SignedPreKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  protected void finalize() {
    Native.SignedPreKeyRecord_Destroy(this.unsafeHandle);
  }

  public SignedPreKeyRecord(int id, long timestamp, ECKeyPair keyPair, byte[] signature) {
    try (
      NativeHandleGuard publicGuard = new NativeHandleGuard(keyPair.getPublicKey());
      NativeHandleGuard privateGuard = new NativeHandleGuard(keyPair.getPrivateKey());
    ) {
      this.unsafeHandle = Native.SignedPreKeyRecord_New(
        id,
        timestamp,
        publicGuard.nativeHandle(),
        privateGuard.nativeHandle(),
        signature);
    }
  }

  public SignedPreKeyRecord(byte[] serialized) throws IOException {
    this.unsafeHandle = Native.SignedPreKeyRecord_Deserialize(serialized);
  }

  public int getId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SignedPreKeyRecord_GetId(guard.nativeHandle());
    }
  }

  public long getTimestamp() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SignedPreKeyRecord_GetTimestamp(guard.nativeHandle());
    }
  }

  public ECKeyPair getKeyPair() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      ECPublicKey publicKey = new ECPublicKey(Native.SignedPreKeyRecord_GetPublicKey(guard.nativeHandle()));
      ECPrivateKey privateKey = new ECPrivateKey(Native.SignedPreKeyRecord_GetPrivateKey(guard.nativeHandle()));
      return new ECKeyPair(publicKey, privateKey);
    }
  }

  public byte[] getSignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SignedPreKeyRecord_GetSignature(guard.nativeHandle());
    }
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SignedPreKeyRecord_GetSerialized(guard.nativeHandle());
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

}

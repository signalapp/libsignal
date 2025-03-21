//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.kem.KEMKeyPair;

public class KyberPreKeyRecord extends NativeHandleGuard.SimpleOwner {
  @Override
  protected void release(long nativeHandle) {
    Native.KyberPreKeyRecord_Destroy(nativeHandle);
  }

  public KyberPreKeyRecord(int id, long timestamp, KEMKeyPair keyPair, byte[] signature) {
    super(
        keyPair.guardedMap(
            (keyPairHandle) ->
                Native.KyberPreKeyRecord_New(id, timestamp, keyPairHandle, signature)));
  }

  // FIXME: This shouldn't be considered a "message".
  public KyberPreKeyRecord(byte[] serialized) throws InvalidMessageException {
    super(
        filterExceptions(
            InvalidMessageException.class, () -> Native.KyberPreKeyRecord_Deserialize(serialized)));
  }

  public int getId() {
    return filterExceptions(() -> guardedMapChecked(Native::KyberPreKeyRecord_GetId));
  }

  public long getTimestamp() {
    return filterExceptions(() -> guardedMapChecked(Native::KyberPreKeyRecord_GetTimestamp));
  }

  public KEMKeyPair getKeyPair() throws InvalidKeyException {
    return new KEMKeyPair(
        filterExceptions(
            InvalidKeyException.class,
            () -> guardedMapChecked(Native::KyberPreKeyRecord_GetKeyPair)));
  }

  public byte[] getSignature() {
    return filterExceptions(() -> guardedMapChecked(Native::KyberPreKeyRecord_GetSignature));
  }

  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::KyberPreKeyRecord_GetSerialized));
  }
}

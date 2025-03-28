//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public class PreKeyRecord extends NativeHandleGuard.SimpleOwner {
  @Override
  protected void release(long nativeHandle) {
    Native.PreKeyRecord_Destroy(nativeHandle);
  }

  public PreKeyRecord(int id, ECKeyPair keyPair) {
    super(
        keyPair
            .getPublicKey()
            .guardedMap(
                (publicKeyHandle) ->
                    keyPair
                        .getPrivateKey()
                        .guardedMap(
                            (privateKeyHandle) ->
                                Native.PreKeyRecord_New(id, publicKeyHandle, privateKeyHandle))));
  }

  // FIXME: This shouldn't be considered a "message".
  public PreKeyRecord(byte[] serialized) throws InvalidMessageException {
    super(
        filterExceptions(
            InvalidMessageException.class, () -> Native.PreKeyRecord_Deserialize(serialized)));
  }

  public int getId() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeyRecord_GetId));
  }

  public ECKeyPair getKeyPair() throws InvalidKeyException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          InvalidKeyException.class,
          () -> {
            ECPublicKey publicKey =
                new ECPublicKey(Native.PreKeyRecord_GetPublicKey(guard.nativeHandle()));
            ECPrivateKey privateKey =
                new ECPrivateKey(Native.PreKeyRecord_GetPrivateKey(guard.nativeHandle()));
            return new ECKeyPair(publicKey, privateKey);
          });
    }
  }

  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeyRecord_GetSerialized));
  }
}

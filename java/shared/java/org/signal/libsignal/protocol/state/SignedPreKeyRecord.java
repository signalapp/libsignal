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

public class SignedPreKeyRecord extends NativeHandleGuard.SimpleOwner {
  @Override
  protected void release(long nativeHandle) {
    Native.SignedPreKeyRecord_Destroy(nativeHandle);
  }

  public SignedPreKeyRecord(int id, long timestamp, ECKeyPair keyPair, byte[] signature) {
    super(
        keyPair
            .getPublicKey()
            .guardedMap(
                (publicKeyHandle) ->
                    keyPair
                        .getPrivateKey()
                        .guardedMap(
                            (privateKeyHandle) ->
                                Native.SignedPreKeyRecord_New(
                                    id, timestamp, publicKeyHandle, privateKeyHandle, signature))));
  }

  // FIXME: This shouldn't be considered a "message".
  public SignedPreKeyRecord(byte[] serialized) throws InvalidMessageException {
    super(
        filterExceptions(
            InvalidMessageException.class,
            () -> Native.SignedPreKeyRecord_Deserialize(serialized)));
  }

  public int getId() {
    return filterExceptions(() -> guardedMapChecked(Native::SignedPreKeyRecord_GetId));
  }

  public long getTimestamp() {
    return filterExceptions(() -> guardedMapChecked(Native::SignedPreKeyRecord_GetTimestamp));
  }

  public ECKeyPair getKeyPair() throws InvalidKeyException {
    return filterExceptions(
        InvalidKeyException.class,
        () ->
            guardedMapChecked(
                (nativeHandle) -> {
                  ECPublicKey publicKey =
                      new ECPublicKey(Native.SignedPreKeyRecord_GetPublicKey(nativeHandle));
                  ECPrivateKey privateKey =
                      new ECPrivateKey(Native.SignedPreKeyRecord_GetPrivateKey(nativeHandle));
                  return new ECKeyPair(publicKey, privateKey);
                }));
  }

  public byte[] getSignature() {
    return filterExceptions(() -> guardedMapChecked(Native::SignedPreKeyRecord_GetSignature));
  }

  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::SignedPreKeyRecord_GetSerialized));
  }
}

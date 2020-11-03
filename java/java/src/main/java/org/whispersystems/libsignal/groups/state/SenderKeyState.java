/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups.state;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;

import com.google.protobuf.InvalidProtocolBufferException;

import static org.whispersystems.libsignal.state.StorageProtos.SenderKeyStateStructure;

/**
 * Represents the state of an individual SenderKey ratchet.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyState {
  private long handle;

  public SenderKeyState(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
    this(id, iteration, chainKey, signatureKey, Optional.<ECPrivateKey>absent());
  }

  public SenderKeyState(int id, int iteration, byte[] chainKey, ECKeyPair signatureKey) {
    this(id, iteration, chainKey, signatureKey.getPublicKey(), Optional.of(signatureKey.getPrivateKey()));
  }

  private SenderKeyState(int id, int iteration, byte[] chainKey,
                        ECPublicKey signatureKeyPublic,
                        Optional<ECPrivateKey> signatureKeyPrivate)
  {
    long signatureKeyPrivateHandle = signatureKeyPrivate.isPresent() ? signatureKeyPrivate.get().nativeHandle() : 0;

    this.handle = Native.SenderKeyState_New(id, iteration, chainKey, signatureKeyPublic.nativeHandle(),
                      signatureKeyPrivateHandle);
  }

  public SenderKeyState(SenderKeyStateStructure senderKeyStateStructure) {
    this.handle = Native.SenderKeyState_Deserialize(senderKeyStateStructure.toByteArray());
  }

  public SenderKeyStateStructure getStructure() {
    try {
      return SenderKeyStateStructure.parseFrom(Native.SenderKeyState_GetSerialized(this.handle));
    } catch (InvalidProtocolBufferException e) {
      throw new AssertionError(e);
    }
  }
}

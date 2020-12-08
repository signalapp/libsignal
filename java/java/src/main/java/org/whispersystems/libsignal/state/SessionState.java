/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.state;

import org.signal.client.internal.Native;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.Chain;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.PendingKeyExchange;
import org.whispersystems.libsignal.state.StorageProtos.SessionStructure.PendingPreKey;
import org.whispersystems.libsignal.util.Pair;
import org.whispersystems.libsignal.util.guava.Optional;

import java.io.IOException;

import java.util.Iterator;
import java.util.List;

import static org.whispersystems.libsignal.state.StorageProtos.SessionStructure;

public class SessionState {
  private SessionStructure sessionStructure;

  static public SessionState initializeAliceSession(IdentityKeyPair identityKey,
                                                    ECKeyPair baseKey,
                                                    IdentityKey theirIdentityKey,
                                                    ECPublicKey theirSignedPreKey,
                                                    ECPublicKey theirRatchetKey) {
  try {
      return new SessionState(Native.SessionState_InitializeAliceSession(identityKey.getPrivateKey().nativeHandle(),
                                                     identityKey.getPublicKey().getPublicKey().nativeHandle(),
                                                     baseKey.getPrivateKey().nativeHandle(),
                                                     baseKey.getPublicKey().nativeHandle(),
                                                     theirIdentityKey.getPublicKey().nativeHandle(),
                                                     theirSignedPreKey.nativeHandle(),
                                                     theirRatchetKey.nativeHandle()));
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  static public SessionState initializeBobSession(IdentityKeyPair identityKey,
                                                  ECKeyPair signedPreKey,
                                                  ECKeyPair ephemeralKey,
                                                  IdentityKey theirIdentityKey,
                                                  ECPublicKey theirBaseKey) {
    try {
      return new SessionState(Native.SessionState_InitializeBobSession(identityKey.getPrivateKey().nativeHandle(),
                                                   identityKey.getPublicKey().getPublicKey().nativeHandle(),
                                                   signedPreKey.getPrivateKey().nativeHandle(),
                                                   signedPreKey.getPublicKey().nativeHandle(),
                                                   ephemeralKey.getPrivateKey().nativeHandle(),
                                                   ephemeralKey.getPublicKey().nativeHandle(),
                                                   theirIdentityKey.getPublicKey().nativeHandle(),
                                                   theirBaseKey.nativeHandle()));
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  public SessionState(byte[] serialized) throws IOException {
    this.sessionStructure = SessionStructure.parseFrom(serialized);
  }

  private static final int MAX_MESSAGE_KEYS = 2000;

  public SessionState() {
    this.sessionStructure = SessionStructure.newBuilder().build();
  }

  public SessionState(SessionStructure sessionStructure) {
    this.sessionStructure = sessionStructure;
  }

  SessionState(SessionState copy) {
    this.sessionStructure = copy.sessionStructure.toBuilder().build();
  }

  SessionStructure getStructure() {
    return sessionStructure;
  }

  public byte[] getAliceBaseKey() {
    return this.sessionStructure.getAliceBaseKey().toByteArray();
  }

  public int getSessionVersion() {
    int sessionVersion = this.sessionStructure.getSessionVersion();

    if (sessionVersion == 0) return 2;
    else                     return sessionVersion;
  }

  public IdentityKey getRemoteIdentityKey() {
    try {
      if (!this.sessionStructure.hasRemoteIdentityPublic()) {
        return null;
      }

      return new IdentityKey(this.sessionStructure.getRemoteIdentityPublic().toByteArray(), 0);
    } catch (InvalidKeyException e) {
      Log.w("SessionRecordV2", e);
      return null;
    }
  }

  public IdentityKey getLocalIdentityKey() {
    try {
      return new IdentityKey(this.sessionStructure.getLocalIdentityPublic().toByteArray(), 0);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public boolean hasSenderChain() {
    return sessionStructure.hasSenderChain();
  }

  private Pair<Chain,Integer> getReceiverChain(ECPublicKey senderEphemeral) {
    List<Chain> receiverChains = sessionStructure.getReceiverChainsList();
    int         index          = 0;

    for (Chain receiverChain : receiverChains) {
      try {
        ECPublicKey chainSenderRatchetKey = Curve.decodePoint(receiverChain.getSenderRatchetKey().toByteArray(), 0);

        if (chainSenderRatchetKey.equals(senderEphemeral)) {
          return new Pair<>(receiverChain,index);
        }
      } catch (InvalidKeyException e) {
        Log.w("SessionRecordV2", e);
     }

     index++;
    }

   return null;
   }

   public byte[] getReceiverChainKeyValue(ECPublicKey senderEphemeral) {
     Pair<Chain,Integer> receiverChainAndIndex = getReceiverChain(senderEphemeral);
     Chain               receiverChain         = receiverChainAndIndex.first();

     if (receiverChain == null) {
       return null;
     } else {
       return receiverChain.getChainKey().getKey().toByteArray();
     }
  }

  public byte[] getSenderChainKeyValue() {
    Chain.ChainKey chainKeyStructure = sessionStructure.getSenderChain().getChainKey();
    return chainKeyStructure.getKey().toByteArray();
  }

  public int getRemoteRegistrationId() {
    return this.sessionStructure.getRemoteRegistrationId();
  }

  public int getLocalRegistrationId() {
    return this.sessionStructure.getLocalRegistrationId();
  }

  public byte[] serialize() {
    return sessionStructure.toByteArray();
  }
}

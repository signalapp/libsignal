/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.state;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.InvalidKeyException;
import java.io.IOException;
import static org.whispersystems.libsignal.state.StorageProtos.SessionStructure;

public class SessionState {
  private long handle;

  @Override
  protected void finalize() {
     Native.SessionState_Destroy(this.handle);
  }

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
    this.handle = Native.SessionState_Deserialize(serialized);
  }

  public SessionState(SessionStructure sessionStructure) {
    this.handle = Native.SessionState_Deserialize(sessionStructure.toByteArray());
  }

  SessionState(long handle) {
    this.handle = handle;
  }

  // Remove this:
  SessionState(SessionState copy) {
    this.handle = copy.handle;
  }

  public byte[] getAliceBaseKey() {
    return Native.SessionState_GetAliceBaseKey(this.handle);
  }

  public int getSessionVersion() {
    return Native.SessionState_GetSessionVersion(this.handle);
  }

  public IdentityKey getRemoteIdentityKey() {
    byte[] keyBytes = Native.SessionState_GetRemoteIdentityKeyPublic(this.handle);

    if (keyBytes == null){
      return null;
    }

    try {
       return new IdentityKey(keyBytes);
    }
    catch(InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public IdentityKey getLocalIdentityKey() {
    byte[] keyBytes = Native.SessionState_GetLocalIdentityKeyPublic(this.handle);
    try {
       return new IdentityKey(keyBytes);
    }
    catch(InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public boolean hasSenderChain() {
    return Native.SessionState_HasSenderChain(this.handle);
  }

  public byte[] getReceiverChainKeyValue(ECPublicKey senderEphemeral) {
    return Native.SessionState_GetReceiverChainKeyValue(this.handle, senderEphemeral.nativeHandle());
  }

  public byte[] getSenderChainKeyValue() {
    return Native.SessionState_GetSenderChainKeyValue(this.handle);
  }

  public int getRemoteRegistrationId() {
    return Native.SessionState_GetRemoteRegistrationId(this.handle);
  }

  public int getLocalRegistrationId() {
    return Native.SessionState_GetLocalRegistrationId(this.handle);
  }

  public byte[] serialize() {
    return Native.SessionState_Serialized(this.handle);
  }

  long nativeHandle() {
    return this.handle;
  }
}

/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import java.io.IOException;

/**
 * A SessionRecord encapsulates the state of an ongoing session.
 *
 * @author Moxie Marlinspike
 */
public class SessionRecord {

  long handle;

  @Override
  protected void finalize() {
     Native.SessionRecord_Destroy(this.handle);
  }

  public SessionRecord() {
    this.handle = Native.SessionRecord_NewFresh();
  }

  public static SessionRecord fromSingleSessionState(byte[] sessionStateBytes) throws IOException {
    return new SessionRecord(new SessionState(sessionStateBytes));
  }

  public SessionRecord(byte[] serialized) throws IOException {
    this.handle = Native.SessionRecord_Deserialize(serialized);
  }

  /**
   * Move the current {@link SessionState} into the list of "previous" session states,
   * and replace the current {@link org.whispersystems.libsignal.state.SessionState}
   * with a fresh reset instance.
   */
  public void archiveCurrentState() {
    Native.SessionRecord_ArchiveCurrentState(this.handle);
  }

  public int getSessionVersion() {
    // return Native.SessionRecord_GetSessionVersion(this.handle);
    return getSessionState().getSessionVersion();
  }

  public int getRemoteRegistrationId() {
    // return Native.SessionRecord_GetRemoteRegistrationId(this.handle);
    return getSessionState().getRemoteRegistrationId();
  }

  public int getLocalRegistrationId() {
    // return Native.SessionRecord_GetLocalRegistrationId(this.handle);
    return getSessionState().getLocalRegistrationId();
  }

  public IdentityKey getRemoteIdentityKey() {
    // return Native.SessionRecord_GetRemoteIdentityKey(this.handle);
    return getSessionState().getRemoteIdentityKey();
  }

  public IdentityKey getLocalIdentityKey() {
    // return Native.SessionRecord_GetLocalIdentityKey(this.handle);
    return getSessionState().getLocalIdentityKey();
  }

  public boolean hasSenderChain() {
    return getSessionState().hasSenderChain();
  }

  /**
   * @return a serialized version of the current SessionRecord.
   */
  public byte[] serialize() {
    return Native.SessionRecord_Serialize(this.handle);
  }

  // Following functions are for internal or testing use and may be removed in the future:

  public byte[] getReceiverChainKeyValue(ECPublicKey senderEphemeral) {
    return getSessionState().getReceiverChainKeyValue(senderEphemeral);
  }

  public byte[] getSenderChainKeyValue() {
    return getSessionState().getSenderChainKeyValue();
  }

  public SessionRecord(SessionState sessionState) {
    this.handle = Native.SessionRecord_FromSessionState(sessionState.nativeHandle());
  }

  public SessionState getSessionState() {
    return new SessionState(Native.SessionRecord_GetSessionState(this.handle));
  }

  public byte[] getAliceBaseKey() {
    return getSessionState().getAliceBaseKey();
  }

  static public SessionRecord initializeAliceSession(IdentityKeyPair identityKey,
                                                     ECKeyPair baseKey,
                                                     IdentityKey theirIdentityKey,
                                                     ECPublicKey theirSignedPreKey,
                                                     ECPublicKey theirRatchetKey) {
    return new SessionRecord(SessionState.initializeAliceSession(identityKey, baseKey,
                                                                 theirIdentityKey,
                                                                 theirSignedPreKey,
                                                                 theirRatchetKey));
  }

  static public SessionRecord initializeBobSession(IdentityKeyPair identityKey,
                                                   ECKeyPair signedPreKey,
                                                   ECKeyPair ephemeralKey,
                                                   IdentityKey theirIdentityKey,
                                                   ECPublicKey theirBaseKey) {

    return new SessionRecord(SessionState.initializeBobSession(identityKey,
                                                               signedPreKey,
                                                               ephemeralKey,
                                                               theirIdentityKey,
                                                               theirBaseKey));
  }

  long nativeHandle() {
    return this.handle;
  }
}

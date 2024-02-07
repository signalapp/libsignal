//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

/**
 * A SessionRecord encapsulates the state of an ongoing session.
 *
 * @author Moxie Marlinspike
 */
public class SessionRecord implements NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.SessionRecord_Destroy(this.unsafeHandle);
  }

  public SessionRecord() {
    this.unsafeHandle = Native.SessionRecord_NewFresh();
  }

  private SessionRecord(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  // FIXME: This shouldn't be considered a "message".
  public SessionRecord(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle =
        filterExceptions(
            InvalidMessageException.class, () -> Native.SessionRecord_Deserialize(serialized));
  }

  /**
   * Move the current SessionState into the list of "previous" session states, and replace the
   * current SessionState with a fresh reset instance.
   */
  public void archiveCurrentState() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      filterExceptions(() -> Native.SessionRecord_ArchiveCurrentState(guard.nativeHandle()));
    }
  }

  public int getSessionVersion() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SessionRecord_GetSessionVersion(guard.nativeHandle()));
    }
  }

  public int getRemoteRegistrationId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.SessionRecord_GetRemoteRegistrationId(guard.nativeHandle()));
    }
  }

  public int getLocalRegistrationId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.SessionRecord_GetLocalRegistrationId(guard.nativeHandle()));
    }
  }

  public IdentityKey getRemoteIdentityKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      byte[] keyBytes =
          filterExceptions(
              InvalidKeyException.class,
              () -> Native.SessionRecord_GetRemoteIdentityKeyPublic(guard.nativeHandle()));

      if (keyBytes == null) {
        return null;
      }

      return new IdentityKey(keyBytes);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public IdentityKey getLocalIdentityKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      byte[] keyBytes =
          filterExceptions(
              InvalidKeyException.class,
              () -> Native.SessionRecord_GetLocalIdentityKeyPublic(guard.nativeHandle()));
      return new IdentityKey(keyBytes);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Returns whether the current session can be used to send messages.
   *
   * <p>If there is no current session, returns {@code false}.
   */
  public boolean hasSenderChain() {
    return hasSenderChain(Instant.now());
  }

  /**
   * Returns whether the current session can be used to send messages.
   *
   * <p>If there is no current session, returns {@code false}.
   *
   * <p>You should only use this overload if you need to test session expiration.
   */
  public boolean hasSenderChain(Instant now) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () ->
              Native.SessionRecord_HasUsableSenderChain(guard.nativeHandle(), now.toEpochMilli()));
    }
  }

  public boolean currentRatchetKeyMatches(ECPublicKey key) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this);
        NativeHandleGuard keyGuard = new NativeHandleGuard(key); ) {
      return filterExceptions(
          () ->
              Native.SessionRecord_CurrentRatchetKeyMatches(
                  guard.nativeHandle(), keyGuard.nativeHandle()));
    }
  }

  /**
   * @return a serialized version of the current SessionRecord.
   */
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SessionRecord_Serialize(guard.nativeHandle()));
    }
  }

  // Following functions are for internal or testing use and may be removed in the future:

  public byte[] getReceiverChainKeyValue(ECPublicKey senderEphemeral) {
    try (NativeHandleGuard guard = new NativeHandleGuard(this);
        NativeHandleGuard ephemeralGuard = new NativeHandleGuard(senderEphemeral); ) {
      return filterExceptions(
          () ->
              Native.SessionRecord_GetReceiverChainKeyValue(
                  guard.nativeHandle(), ephemeralGuard.nativeHandle()));
    }
  }

  public byte[] getSenderChainKeyValue() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.SessionRecord_GetSenderChainKeyValue(guard.nativeHandle()));
    }
  }

  public byte[] getAliceBaseKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SessionRecord_GetAliceBaseKey(guard.nativeHandle()));
    }
  }

  public static SessionRecord initializeAliceSession(
      IdentityKeyPair identityKey,
      ECKeyPair baseKey,
      IdentityKey theirIdentityKey,
      ECPublicKey theirSignedPreKey,
      ECPublicKey theirRatchetKey) {
    try (NativeHandleGuard identityPrivateGuard =
            new NativeHandleGuard(identityKey.getPrivateKey());
        NativeHandleGuard identityPublicGuard =
            new NativeHandleGuard(identityKey.getPublicKey().getPublicKey());
        NativeHandleGuard basePrivateGuard = new NativeHandleGuard(baseKey.getPrivateKey());
        NativeHandleGuard basePublicGuard = new NativeHandleGuard(baseKey.getPublicKey());
        NativeHandleGuard theirIdentityGuard =
            new NativeHandleGuard(theirIdentityKey.getPublicKey());
        NativeHandleGuard theirSignedPreKeyGuard = new NativeHandleGuard(theirSignedPreKey);
        NativeHandleGuard theirRatchetKeyGuard = new NativeHandleGuard(theirRatchetKey); ) {
      return new SessionRecord(
          filterExceptions(
              () ->
                  Native.SessionRecord_InitializeAliceSession(
                      identityPrivateGuard.nativeHandle(),
                      identityPublicGuard.nativeHandle(),
                      basePrivateGuard.nativeHandle(),
                      basePublicGuard.nativeHandle(),
                      theirIdentityGuard.nativeHandle(),
                      theirSignedPreKeyGuard.nativeHandle(),
                      theirRatchetKeyGuard.nativeHandle())));
    }
  }

  public static SessionRecord initializeBobSession(
      IdentityKeyPair identityKey,
      ECKeyPair signedPreKey,
      ECKeyPair ephemeralKey,
      IdentityKey theirIdentityKey,
      ECPublicKey theirBaseKey) {
    try (NativeHandleGuard identityPrivateGuard =
            new NativeHandleGuard(identityKey.getPrivateKey());
        NativeHandleGuard identityPublicGuard =
            new NativeHandleGuard(identityKey.getPublicKey().getPublicKey());
        NativeHandleGuard signedPreKeyPrivateGuard =
            new NativeHandleGuard(signedPreKey.getPrivateKey());
        NativeHandleGuard signedPreKeyPublicGuard =
            new NativeHandleGuard(signedPreKey.getPublicKey());
        NativeHandleGuard ephemeralPrivateGuard =
            new NativeHandleGuard(ephemeralKey.getPrivateKey());
        NativeHandleGuard ephemeralPublicGuard =
            new NativeHandleGuard(ephemeralKey.getPublicKey());
        NativeHandleGuard theirIdentityGuard =
            new NativeHandleGuard(theirIdentityKey.getPublicKey());
        NativeHandleGuard theirBaseKeyGuard = new NativeHandleGuard(theirBaseKey); ) {
      return new SessionRecord(
          filterExceptions(
              () ->
                  Native.SessionRecord_InitializeBobSession(
                      identityPrivateGuard.nativeHandle(),
                      identityPublicGuard.nativeHandle(),
                      signedPreKeyPrivateGuard.nativeHandle(),
                      signedPreKeyPublicGuard.nativeHandle(),
                      ephemeralPrivateGuard.nativeHandle(),
                      ephemeralPublicGuard.nativeHandle(),
                      theirIdentityGuard.nativeHandle(),
                      theirBaseKeyGuard.nativeHandle())));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}

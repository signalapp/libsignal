//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

/**
 * A SessionRecord encapsulates the state of an ongoing session.
 *
 * @author Moxie Marlinspike
 */
public class SessionRecord extends NativeHandleGuard.SimpleOwner {

  @Override
  protected void release(long nativeHandle) {
    Native.SessionRecord_Destroy(nativeHandle);
  }

  public SessionRecord() {
    super(Native.SessionRecord_NewFresh());
  }

  @CalledFromNative
  private SessionRecord(long nativeHandle) {
    super(nativeHandle);
  }

  // FIXME: This shouldn't be considered a "message".
  public SessionRecord(byte[] serialized) throws InvalidMessageException {
    super(
        filterExceptions(
            InvalidMessageException.class, () -> Native.SessionRecord_Deserialize(serialized)));
  }

  /**
   * Move the current SessionState into the list of "previous" session states, and replace the
   * current SessionState with a fresh reset instance.
   */
  public void archiveCurrentState() {
    filterExceptions(() -> guardedRunChecked(Native::SessionRecord_ArchiveCurrentState));
  }

  public int getSessionVersion() {
    return filterExceptions(() -> guardedMapChecked(Native::SessionRecord_GetSessionVersion));
  }

  public int getRemoteRegistrationId() {
    return filterExceptions(() -> guardedMapChecked(Native::SessionRecord_GetRemoteRegistrationId));
  }

  public int getLocalRegistrationId() {
    return filterExceptions(() -> guardedMapChecked(Native::SessionRecord_GetLocalRegistrationId));
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
    return filterExceptions(
        () ->
            guardedMapChecked(
                (nativeHandle) ->
                    Native.SessionRecord_HasUsableSenderChain(nativeHandle, now.toEpochMilli())));
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
    return filterExceptions(() -> guardedMapChecked(Native::SessionRecord_Serialize));
  }
}

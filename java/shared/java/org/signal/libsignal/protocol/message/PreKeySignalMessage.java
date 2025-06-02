//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.message;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.Optional;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public class PreKeySignalMessage extends NativeHandleGuard.SimpleOwner
    implements CiphertextMessage, NativeHandleGuard.Owner {

  @Override
  protected void release(long nativeHandle) {
    Native.PreKeySignalMessage_Destroy(nativeHandle);
  }

  public PreKeySignalMessage(byte[] serialized)
      throws InvalidMessageException,
          InvalidVersionException,
          LegacyMessageException,
          InvalidKeyException {
    super(
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            LegacyMessageException.class,
            InvalidKeyException.class,
            () -> Native.PreKeySignalMessage_Deserialize(serialized)));
  }

  @CalledFromNative
  public PreKeySignalMessage(long nativeHandle) {
    super(nativeHandle);
  }

  public int getMessageVersion() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeySignalMessage_GetVersion));
  }

  public IdentityKey getIdentityKey() {
    return new IdentityKey(
        filterExceptions(() -> guardedMapChecked(Native::PreKeySignalMessage_GetIdentityKey)));
  }

  public int getRegistrationId() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeySignalMessage_GetRegistrationId));
  }

  public Optional<Integer> getPreKeyId() {
    int pre_key =
        filterExceptions(() -> guardedMapChecked(Native::PreKeySignalMessage_GetPreKeyId));
    if (pre_key < 0) {
      return Optional.empty();
    } else {
      return Optional.of(pre_key);
    }
  }

  public int getSignedPreKeyId() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeySignalMessage_GetSignedPreKeyId));
  }

  public ECPublicKey getBaseKey() {
    return new ECPublicKey(guardedMap(Native::PreKeySignalMessage_GetBaseKey));
  }

  public SignalMessage getWhisperMessage() {
    return new SignalMessage(guardedMap(Native::PreKeySignalMessage_GetSignalMessage));
  }

  @Override
  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeySignalMessage_GetSerialized));
  }

  @Override
  public int getType() {
    return CiphertextMessage.PREKEY_TYPE;
  }
}

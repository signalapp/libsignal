/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;

public class PreKeySignalMessage implements CiphertextMessage, NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override
  protected void finalize() {
     Native.PreKeySignalMessage_Destroy(this.unsafeHandle);
  }

  public PreKeySignalMessage(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException
  {
    this.unsafeHandle = Native.PreKeySignalMessage_Deserialize(serialized);
  }

  public PreKeySignalMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public int getMessageVersion() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeySignalMessage_GetVersion(guard.nativeHandle());
    }
  }

  public IdentityKey getIdentityKey() throws InvalidKeyException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new IdentityKey(Native.PreKeySignalMessage_GetIdentityKey(guard.nativeHandle()), 0);
    }
  }

  public int getRegistrationId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeySignalMessage_GetRegistrationId(guard.nativeHandle());
    }
  }

  public Optional<Integer> getPreKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      int pre_key = Native.PreKeySignalMessage_GetPreKeyId(guard.nativeHandle());
      if (pre_key < 0) {
        return Optional.absent();
      } else {
        return Optional.of(pre_key);
      }
    }
  }

  public int getSignedPreKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeySignalMessage_GetSignedPreKeyId(guard.nativeHandle());
    }
  }

  public ECPublicKey getBaseKey() throws InvalidKeyException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(Native.PreKeySignalMessage_GetBaseKey(guard.nativeHandle()));
    }
  }

  public SignalMessage getWhisperMessage() throws InvalidMessageException, LegacyMessageException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new SignalMessage(Native.PreKeySignalMessage_GetSignalMessage(guard.nativeHandle()));
    }
  }

  @Override
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeySignalMessage_GetSerialized(guard.nativeHandle());
    }
  }

  @Override
  public int getType() {
    return CiphertextMessage.PREKEY_TYPE;
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}

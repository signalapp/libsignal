/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.message;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

import java.util.Optional;

public class PreKeySignalMessage implements CiphertextMessage, NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
     Native.PreKeySignalMessage_Destroy(this.unsafeHandle);
  }

  public PreKeySignalMessage(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException, LegacyMessageException, InvalidKeyException
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

  public IdentityKey getIdentityKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new IdentityKey(Native.PreKeySignalMessage_GetIdentityKey(guard.nativeHandle()));
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
        return Optional.empty();
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

  public ECPublicKey getBaseKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(Native.PreKeySignalMessage_GetBaseKey(guard.nativeHandle()));
    }
  }

  public SignalMessage getWhisperMessage() {
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

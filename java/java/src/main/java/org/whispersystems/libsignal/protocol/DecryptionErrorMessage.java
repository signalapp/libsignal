/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;

import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;

public final class DecryptionErrorMessage implements NativeHandleGuard.Owner {

  final long unsafeHandle;

  @Override
  protected void finalize() {
     Native.DecryptionErrorMessage_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return unsafeHandle;
  }

  DecryptionErrorMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public DecryptionErrorMessage(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle = Native.DecryptionErrorMessage_Deserialize(serialized);
  }

  public static DecryptionErrorMessage forOriginalMessage(byte[] originalBytes, int messageType, long timestamp, int originalSenderDeviceId) {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_ForOriginalMessage(originalBytes, messageType, timestamp, originalSenderDeviceId));
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.DecryptionErrorMessage_GetSerialized(guard.nativeHandle());
    }
  }

  public Optional<ECPublicKey> getRatchetKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      long keyHandle = Native.DecryptionErrorMessage_GetRatchetKey(guard.nativeHandle());
      if (keyHandle == 0) {
        return Optional.absent();
      } else {
        return Optional.of(new ECPublicKey(keyHandle));
      }
    }
  }

  public long getTimestamp() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.DecryptionErrorMessage_GetTimestamp(guard.nativeHandle());
    }
  }

  public int getDeviceId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.DecryptionErrorMessage_GetDeviceId(guard.nativeHandle());
    }
  }

  /// For testing only
  public static DecryptionErrorMessage extractFromSerializedContent(byte[] serializedContentBytes) throws InvalidMessageException {
    return new DecryptionErrorMessage(
      Native.DecryptionErrorMessage_ExtractFromSerializedContent(serializedContentBytes));
  }
}

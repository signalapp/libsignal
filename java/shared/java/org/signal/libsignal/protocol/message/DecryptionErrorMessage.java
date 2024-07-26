//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.message;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.Optional;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public final class DecryptionErrorMessage implements NativeHandleGuard.Owner {

  final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.DecryptionErrorMessage_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return unsafeHandle;
  }

  DecryptionErrorMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public DecryptionErrorMessage(byte[] serialized)
      throws InvalidKeyException, InvalidMessageException {
    this.unsafeHandle =
        filterExceptions(
            InvalidKeyException.class,
            InvalidMessageException.class,
            () -> Native.DecryptionErrorMessage_Deserialize(serialized));
  }

  public static DecryptionErrorMessage forOriginalMessage(
      byte[] originalBytes, int messageType, long timestamp, int originalSenderDeviceId) {
    return new DecryptionErrorMessage(
        filterExceptions(
            () ->
                Native.DecryptionErrorMessage_ForOriginalMessage(
                    originalBytes, messageType, timestamp, originalSenderDeviceId)));
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.DecryptionErrorMessage_GetSerialized(guard.nativeHandle()));
    }
  }

  public Optional<ECPublicKey> getRatchetKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      long keyHandle = Native.DecryptionErrorMessage_GetRatchetKey(guard.nativeHandle());
      if (keyHandle == 0) {
        return Optional.empty();
      } else {
        return Optional.of(new ECPublicKey(keyHandle));
      }
    }
  }

  public long getTimestamp() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.DecryptionErrorMessage_GetTimestamp(guard.nativeHandle()));
    }
  }

  public int getDeviceId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.DecryptionErrorMessage_GetDeviceId(guard.nativeHandle()));
    }
  }

  /// For testing only
  public static DecryptionErrorMessage extractFromSerializedContent(byte[] serializedContentBytes)
      throws InvalidMessageException {
    return new DecryptionErrorMessage(
        filterExceptions(
            InvalidMessageException.class,
            () ->
                Native.DecryptionErrorMessage_ExtractFromSerializedContent(
                    serializedContentBytes)));
  }
}

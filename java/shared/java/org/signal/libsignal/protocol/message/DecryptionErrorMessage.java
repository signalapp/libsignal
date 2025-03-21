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

public final class DecryptionErrorMessage extends NativeHandleGuard.SimpleOwner {

  @Override
  protected void release(long nativeHandle) {
    Native.DecryptionErrorMessage_Destroy(nativeHandle);
  }

  DecryptionErrorMessage(long nativeHandle) {
    super(nativeHandle);
  }

  public DecryptionErrorMessage(byte[] serialized)
      throws InvalidKeyException, InvalidMessageException {
    super(
        filterExceptions(
            InvalidKeyException.class,
            InvalidMessageException.class,
            () -> Native.DecryptionErrorMessage_Deserialize(serialized)));
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
    return filterExceptions(() -> guardedMapChecked(Native::DecryptionErrorMessage_GetSerialized));
  }

  public Optional<ECPublicKey> getRatchetKey() {
    long keyHandle = guardedMap(Native::DecryptionErrorMessage_GetRatchetKey);
    if (keyHandle == 0) {
      return Optional.empty();
    } else {
      return Optional.of(new ECPublicKey(keyHandle));
    }
  }

  public long getTimestamp() {
    return filterExceptions(() -> guardedMapChecked(Native::DecryptionErrorMessage_GetTimestamp));
  }

  public int getDeviceId() {
    return filterExceptions(() -> guardedMapChecked(Native::DecryptionErrorMessage_GetDeviceId));
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

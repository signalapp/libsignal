//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.message;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;

public final class PlaintextContent extends NativeHandleGuard.SimpleOwner
    implements CiphertextMessage, NativeHandleGuard.Owner {

  @Override
  protected void release(long nativeHandle) {
    Native.PlaintextContent_Destroy(nativeHandle);
  }

  @CalledFromNative
  @SuppressWarnings("unused")
  private PlaintextContent(long nativeHandle) {
    super(nativeHandle);
  }

  public PlaintextContent(DecryptionErrorMessage message) {
    super(message.guardedMap(Native::PlaintextContent_FromDecryptionErrorMessage));
  }

  public PlaintextContent(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException {
    super(
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            () -> Native.PlaintextContent_Deserialize(serialized)));
  }

  @Override
  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::PlaintextContent_GetSerialized));
  }

  @Override
  public int getType() {
    return CiphertextMessage.PLAINTEXT_CONTENT_TYPE;
  }

  public byte[] getBody() {
    return filterExceptions(() -> guardedMapChecked(Native::PlaintextContent_GetBody));
  }
}

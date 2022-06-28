/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.message;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;

public final class PlaintextContent implements CiphertextMessage, NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
     Native.PlaintextContent_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return unsafeHandle;
  }

  // Used by Rust.
  @SuppressWarnings("unused")
  private PlaintextContent(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public PlaintextContent(DecryptionErrorMessage message) {
    try (NativeHandleGuard messageGuard = new NativeHandleGuard(message)) {
      this.unsafeHandle = Native.PlaintextContent_FromDecryptionErrorMessage(messageGuard.nativeHandle());
    }
  }

  public PlaintextContent(byte[] serialized) throws InvalidMessageException, InvalidVersionException {
    unsafeHandle = Native.PlaintextContent_Deserialize(serialized);
  }

  @Override
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PlaintextContent_GetSerialized(guard.nativeHandle());
    }
  }

  @Override
  public int getType() {
    return CiphertextMessage.PLAINTEXT_CONTENT_TYPE;
  }

  public byte[] getBody() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PlaintextContent_GetBody(guard.nativeHandle());
    }
  }
}

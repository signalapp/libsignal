/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;

import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.util.guava.Optional;

public final class PlaintextContent implements CiphertextMessage, NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override
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

/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;

import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.util.guava.Optional;

public final class PlaintextContent implements CiphertextMessage {

  private final long handle;

  @Override
  protected void finalize() {
     Native.PlaintextContent_Destroy(this.handle);
  }

  public long nativeHandle() {
    return handle;
  }

  // Used by Rust.
  @SuppressWarnings("unused")
  private PlaintextContent(long handle) {
    this.handle = handle;
  }

  public PlaintextContent(DecryptionErrorMessage message) {
    handle = Native.PlaintextContent_FromDecryptionErrorMessage(message.handle);
  }

  @Override
  public byte[] serialize() {
    return Native.PlaintextContent_GetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.PLAINTEXT_CONTENT_TYPE;
  }

  public byte[] getBody() {
    return Native.PlaintextContent_GetBody(this.handle);
  }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.incrementalmac;

import java.io.IOException;
import java.io.OutputStream;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public final class IncrementalMacOutputStream extends OutputStream {
  private final NativeHandleGuard.CloseableOwner handleOwner;
  private final OutputStream digestStream;
  private final OutputStream inner;
  private boolean closed = false;

  public IncrementalMacOutputStream(
      OutputStream inner, byte[] key, ChunkSizeChoice sizeChoice, OutputStream digestStream) {
    int chunkSize = sizeChoice.getSizeInBytes();
    this.inner = inner;
    this.digestStream = digestStream;
    this.handleOwner =
        new NativeHandleGuard.CloseableOwner(Native.IncrementalMac_Initialize(key, chunkSize)) {
          @Override
          protected void release(long nativeHandle) {
            Native.IncrementalMac_Destroy(nativeHandle);
          }
        };
  }

  @Override
  public void write(byte[] buffer) throws IOException {
    this.inner.write(buffer);
    byte[] digestIncrement =
        this.handleOwner.guardedMap(
            (handle) -> Native.IncrementalMac_Update(handle, buffer, 0, buffer.length));
    digestStream.write(digestIncrement);
  }

  @Override
  public void write(byte[] buffer, int offset, int length) throws IOException {
    this.inner.write(buffer, offset, length);
    byte[] digestIncrement =
        this.handleOwner.guardedMap(
            (handle) -> Native.IncrementalMac_Update(handle, buffer, offset, length));
    digestStream.write(digestIncrement);
  }

  @Override
  public void write(int b) throws IOException {
    // According to the spec the narrowing conversion to byte is expected here
    byte[] bytes = {(byte) b};
    byte[] digestIncrement =
        this.handleOwner.guardedMap((handle) -> Native.IncrementalMac_Update(handle, bytes, 0, 1));
    this.inner.write(b);
    this.digestStream.write(digestIncrement);
  }

  @Override
  public void flush() throws IOException {
    this.inner.flush();
    digestStream.flush();
  }

  @Override
  public void close() throws IOException {
    if (this.closed) {
      return;
    }
    this.closed = true;
    try {
      flush();
    } catch (IOException ignored) {
    }
    byte[] digestIncrement = this.handleOwner.guardedMap(Native::IncrementalMac_Finalize);
    digestStream.write(digestIncrement);
    this.handleOwner.close();

    // Intentionally not closing the inner stream, as it seems to be causing
    // problems on Android
    this.digestStream.close();
  }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.incrementalmac;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import org.signal.libsignal.internal.Native;

public final class IncrementalMacInputStream extends InputStream {
  private static final int MAX_BUFFER_SIZE = 8192;
  private final long validatingMac;

  private final ReadableByteChannel inner;
  private boolean closed = false;

  private ByteBuffer currentChunk;

  public IncrementalMacInputStream(
      InputStream inner, byte[] key, ChunkSizeChoice sizeChoice, byte[] digest) {
    int chunkSize = sizeChoice.getSizeInBytes();
    this.currentChunk = ByteBuffer.allocateDirect(chunkSize);
    this.currentChunk.limit(0);
    this.validatingMac = Native.ValidatingMac_Initialize(key, chunkSize, digest);
    this.inner = Channels.newChannel(inner);
  }

  @Override
  public int read() throws IOException {
    byte[] bytes = new byte[1];
    int read = this.readInternal(bytes, 0, 1);
    return (read < 0) ? -1 : (int) bytes[0];
  }

  @Override
  public int read(byte[] bytes, int offset, int length) throws IOException {
    return this.readInternal(bytes, offset, length);
  }

  @Override
  public void close() throws IOException {
    if (this.closed) {
      return;
    }
    this.inner.close();
    Native.ValidatingMac_Destroy(this.validatingMac);
    this.closed = true;
  }

  private int readInternal(byte[] bytes, int offset, int requestedLen) throws IOException {
    if (!this.currentChunk.hasRemaining()) {
      this.currentChunk.clear();
      int bytesRead = this.inner.read(this.currentChunk);
      this.currentChunk.flip();
      if (bytesRead <= 0) {
        return -1;
      }
      this.validateChunk(this.currentChunk.slice(), this.currentChunk.capacity());
    }
    int bytesToRead = Math.min(this.currentChunk.remaining(), requestedLen);
    this.currentChunk.get(bytes, offset, bytesToRead);
    return bytesToRead;
  }

  private void validateChunk(ByteBuffer chunk, int expectedChunkSize) throws IOException {
    // Should only be called right after the chunk (full or incomplete) is read.
    // chunk is a slice of this.currentChunk therefore limit() and capacity()
    // can be used interchangeably.
    assert chunk.limit() == chunk.capacity() : "Must be invoked with ByteBuffer.slice()";
    boolean isFullChunkAvailable = chunk.limit() == expectedChunkSize;
    assertValidBytes(validateChunkImpl(chunk));
    if (!isFullChunkAvailable) {
      assertValidBytes(Native.ValidatingMac_Finalize(this.validatingMac));
    }
  }

  private static void assertValidBytes(int validBytesCount) throws InvalidMacException {
    if (validBytesCount < 0) {
      throw new InvalidMacException();
    }
  }

  private int validateChunkImpl(ByteBuffer chunk) {
    int validBytes = 0;
    int bufferSize = Math.min(chunk.limit(), MAX_BUFFER_SIZE);
    // Using a smaller buffer and a loop because ByteBuffer.get requires a
    // managed byte[] but we want to avoid allocating whole chunks in managed
    // heap
    byte[] buffer = new byte[bufferSize];
    while (chunk.hasRemaining()) {
      int currentlyValidating = Math.min(bufferSize, chunk.remaining());
      chunk.get(buffer, 0, currentlyValidating);
      // Because we are reading one chunk at a time only the last update will return a non-zero
      // value
      validBytes = Native.ValidatingMac_Update(this.validatingMac, buffer, 0, currentlyValidating);
      assert validBytes == 0 || validBytes == -1 || validBytes == chunk.limit()
          : "Unexpected incremental mac update result";
    }
    return validBytes;
  }
}

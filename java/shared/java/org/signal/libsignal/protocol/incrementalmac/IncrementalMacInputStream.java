//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.incrementalmac;

import java.io.IOException;
import java.io.InputStream;
import org.signal.libsignal.internal.Native;

public final class IncrementalMacInputStream extends InputStream {
  private final long validatingMac;

  private final InputStream inner;
  private boolean closed = false;

  private byte[] currentChunk;
  // position in the currentChunk to start reading from
  private int readPos;
  // position in the currentChunk past the index of the last readable byte
  private int writePos;

  public IncrementalMacInputStream(
      InputStream inner, byte[] key, ChunkSizeChoice sizeChoice, byte[] digest) {
    int chunkSize = sizeChoice.getSizeInBytes();
    this.readPos = 0;
    this.writePos = 0;
    this.currentChunk = new byte[chunkSize];
    this.validatingMac = Native.ValidatingMac_Initialize(key, chunkSize, digest);
    this.inner = inner;
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
    if (this.readPos == this.writePos) {
      int bytesRead = this.readBuffer(this.inner, this.currentChunk);
      if (bytesRead == 0) {
        return -1;
      }
      this.writePos = bytesRead;
      this.readPos = 0;
      this.validateChunk();
    }
    int availableToRead = this.writePos - this.readPos;
    int bytesToRead = Math.min(availableToRead, requestedLen);
    System.arraycopy(this.currentChunk, this.readPos, bytes, offset, bytesToRead);
    this.readPos += bytesToRead;
    return bytesToRead;
  }

  private void validateChunk() throws IOException {
    // Supposed to only be called when the chunk of part thereof is read
    // readPos will be 0 and writePos will be the amount of data to be verified.
    int validBytes =
        Native.ValidatingMac_Update(this.validatingMac, this.currentChunk, 0, this.writePos);
    if (this.writePos < this.currentChunk.length) {
      // this is the last sub-chunk
      validBytes += Native.ValidatingMac_Finalize(this.validatingMac);
    }
    if (validBytes < 0) {
      throw new InvalidMacException();
    }
  }

  private int readBuffer(InputStream src, byte[] bytes) throws IOException {
    int totalReadBytes = 0;
    while (totalReadBytes < bytes.length) {
      int readBytes = src.read(bytes, totalReadBytes, bytes.length - totalReadBytes);
      if (readBytes < 0) {
        break;
      }
      totalReadBytes += readBytes;
    }
    return totalReadBytes;
  }
}

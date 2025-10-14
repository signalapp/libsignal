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
import org.signal.libsignal.internal.NativeHandleGuard;

public final class IncrementalMacInputStream extends InputStream {
  private final NativeHandleGuard.CloseableOwner handleOwner;
  private final int chunkSize;

  private final MaybeEmptyChannel channel;
  private boolean closed = false;
  private boolean eof = false;

  private ReadState readState;

  private final ByteBuffer currentChunk;

  private static final int VALIDATION_BUFFER_SIZE = 8192;
  private final byte[] singleByteBuffer = new byte[1];
  private final byte[] chunkValidationBuffer;

  IncrementalMacInputStream(
      ReadableByteChannel channel,
      byte[] key,
      ChunkSizeChoice sizeChoice,
      byte[] digest,
      boolean useDirectBuffer)
      throws InvalidMacException {
    this.chunkSize = sizeChoice.getSizeInBytes();
    this.currentChunk =
        useDirectBuffer ? ByteBuffer.allocateDirect(chunkSize) : ByteBuffer.allocate(chunkSize);
    this.chunkValidationBuffer =
        this.currentChunk.hasArray() ? null : new byte[VALIDATION_BUFFER_SIZE];
    this.readState = ReadState.READ_FROM_INPUT;
    this.channel = new MaybeEmptyChannel(channel);

    long handle = Native.ValidatingMac_Initialize(key, chunkSize, digest);
    if (handle == 0) {
      throw new InvalidMacException("invalid configuration data");
    }

    this.handleOwner =
        new NativeHandleGuard.CloseableOwner(handle) {
          @Override
          protected void release(long nativeHandle) {
            Native.ValidatingMac_Destroy(nativeHandle);
          }
        };
  }

  public IncrementalMacInputStream(
      InputStream input, byte[] key, ChunkSizeChoice sizeChoice, byte[] digest)
      throws InvalidMacException {
    this(Channels.newChannel(input), key, sizeChoice, digest, true);
  }

  /**
   * Read a single byte from input.
   *
   * <p>Tries to read at least one byte. In practice, it means the whole chunk will have to be read
   * before even a single byte can be "released".
   *
   * <p>This method is here to satisfy the {@link InputStream} interface, but should be avoided if
   * possible. Prefer {@link #read(byte[], int, int)}.
   */
  @Override
  public int read() throws IOException {
    int read = 0;
    while (read == 0) {
      read = this.readInternal(this.singleByteBuffer, 0, 1);
    }
    return (read == -1) ? -1 : Byte.toUnsignedInt(this.singleByteBuffer[0]);
  }

  /**
   * Read several bytes into the destination array.
   *
   * <p>In a slight deviation from the {@link InputStream} API semantics, this method may return 0
   * as a way to signal to the caller that no bytes can be safely released. Subsequent reads will
   * eventually return a non-zero value (either a positive number of bytes read, or -1 if the end of
   * the input has been reached).
   */
  @Override
  public int read(byte[] bytes, int offset, int length) throws IOException {
    if (offset + length > bytes.length) {
      throw new IllegalArgumentException("Destination buffer is not large enough");
    }

    return this.readInternal(bytes, offset, length);
  }

  @Override
  public void close() throws IOException {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.channel.close();
    this.handleOwner.close();
  }

  // Read implementation for the READ_FROM_INPUT state.
  // In it, we are filling the currentChunk reading from the input channel.
  // Once there is a full chunk worth of data (or if we have reached the end of
  // input), the chunk is validated and the state is switched to RELEASE_SAFE_BYTES.
  // Notably, this method does not depend on any of the read's arguments' values,
  // and can naturally only return "end of stream" and "chunk has not been fully read".
  private ReadChunkResult readFromInput() throws IOException {
    // Channel read will try to fill the whole buffer
    int bytesRead = this.channel.read(this.currentChunk);

    if (bytesRead == -1) {
      this.eof = true;
      if (!this.channel.hasAtLeastOneByteBeenRead) {
        // This is special case for validating empty inputs.
        // It does not matter what byte[] we pass in since both offset and length are 0.
        this.handleOwner.guardedRun(
            (handle) -> Native.ValidatingMac_Update(handle, this.singleByteBuffer, 0, 0));
        return ReadChunkResult.EOF;
      }
    }

    // We have reached the chunk boundary or end of input, and it is now safe to validate/finalize
    if (!this.currentChunk.hasRemaining() || this.eof) {
      this.currentChunk.flip();
      this.validateChunk(this.currentChunk.slice());
      // Since validation is performed on the slice, the state of currentChunk is exactly what
      // we should be releasing bytes from.
      this.readState = ReadState.RELEASE_SAFE_BYTES;
    }
    return ReadChunkResult.PARTIAL_CHUNK_READ;
  }

  // Read implementation for the RELEASE_SAFE_BYTES state.
  // In it, we are actually "returning" the validated bytes from current chunk by
  // copying them into the destination byte array.
  // Once the entirety of the chunk (full or partial) has been consumed
  // by the caller, the state changes back to READ_FROM_INPUT.
  private int releaseSafeBytes(byte[] bytes, int offset, int requestedLen) throws IOException {
    // We have reached the end of input and there is nothing else to release
    if (this.currentChunk.hasRemaining()) {
      int bytesToRelease = Math.min(this.currentChunk.remaining(), requestedLen);
      this.currentChunk.get(bytes, offset, bytesToRelease);
      return bytesToRelease;
    } else {
      // Reached the end of the input stream and there are no bytes left to release
      if (this.eof) {
        return -1;
      }
      this.currentChunk.clear();
      this.readState = ReadState.READ_FROM_INPUT;
      return 0;
    }
  }

  private int readInternal(byte[] bytes, int offset, int requestedLen) throws IOException {
    if (this.closed) {
      throw new IOException("Stream is closed");
    }

    return switch (this.readState) {
      case READ_FROM_INPUT -> this.readFromInput().getValue();
      case RELEASE_SAFE_BYTES -> this.releaseSafeBytes(bytes, offset, requestedLen);
    };
  }

  private void validateChunk(ByteBuffer chunk) throws IOException {
    // Should only be called right after the chunk (full or incomplete) is read.
    // chunk is a slice of this.currentChunk therefore limit() and capacity()
    // can be used interchangeably.
    assert chunk.limit() == chunk.capacity() : "Must be invoked with ByteBuffer.slice()";
    // need to validate even if the chunk is partial
    assertValidBytes(validateChunkImpl(chunk));
    if (this.eof) {
      int validBytes = this.handleOwner.guardedMap(Native::ValidatingMac_Finalize);
      assertValidBytes(validBytes);
    }
  }

  private static void assertValidBytes(int validBytesCount) throws InvalidMacException {
    if (validBytesCount < 0) {
      throw new InvalidMacException();
    }
  }

  private int validateChunkImpl(ByteBuffer chunk) {
    // If the direct buffer has an underlying array available,
    // we can validate all the bytes in the current chunk in one shot
    // without needing to allocate anything.
    return chunk.hasArray()
        ? validateChunkBackedByArray(chunk)
        : validateChunkWithExtraBuffer(chunk);
  }

  private int validateChunkWithExtraBuffer(ByteBuffer chunk) {
    int validBytes = 0;
    // Potentially using a smaller buffer and a loop because ByteBuffer.get requires
    // a managed byte[] and we want to avoid allocating whole chunks in managed heap
    int bufferLimit = Math.min(chunk.limit(), VALIDATION_BUFFER_SIZE);
    while (chunk.hasRemaining()) {
      int currentlyValidating = Math.min(bufferLimit, chunk.remaining());
      chunk.get(this.chunkValidationBuffer, 0, currentlyValidating);
      // Because we are reading one chunk at a time only the last update will return a non-zero
      // value
      validBytes =
          this.handleOwner.guardedMap(
              (handle) ->
                  Native.ValidatingMac_Update(
                      handle, this.chunkValidationBuffer, 0, currentlyValidating));
      assert validBytes == 0 || validBytes == -1 || validBytes == this.chunkSize
          : "Unexpected incremental mac update result";
    }
    return validBytes;
  }

  private int validateChunkBackedByArray(ByteBuffer chunk) {
    int validBytes;
    int arrayOffset = chunk.arrayOffset();
    validBytes =
        this.handleOwner.guardedMap(
            (handle) ->
                Native.ValidatingMac_Update(
                    handle,
                    chunk.array(),
                    // chunk here is a slice, so its pos should be 0 therefore using arrayOffset is
                    // correct
                    arrayOffset,
                    // similarly we can use chunk.limit for the length
                    chunk.limit()));
    assert validBytes == 0 || validBytes == -1 || validBytes == this.chunkSize
        : "Unexpected incremental mac update result";
    // We don't need to update chunk's position. This is a throwaway slice anyway.
    return validBytes;
  }

  private enum ReadState {
    READ_FROM_INPUT,
    RELEASE_SAFE_BYTES
  }

  private enum ReadChunkResult {
    PARTIAL_CHUNK_READ(0),
    EOF(-1);

    private final int value;

    ReadChunkResult(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }
  }

  private static class MaybeEmptyChannel implements ReadableByteChannel {

    private final ReadableByteChannel inner;
    private boolean hasAtLeastOneByteBeenRead = false;

    private MaybeEmptyChannel(ReadableByteChannel inner) {
      this.inner = inner;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
      int result = this.inner.read(dst);
      if (result > 0) {
        this.hasAtLeastOneByteBeenRead = true;
      }
      return result;
    }

    @Override
    public boolean isOpen() {
      return this.inner.isOpen();
    }

    @Override
    public void close() throws IOException {
      this.inner.close();
    }
  }
}

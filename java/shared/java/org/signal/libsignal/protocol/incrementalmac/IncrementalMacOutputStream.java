//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.incrementalmac;

import org.signal.libsignal.internal.Native;

import java.io.IOException;
import java.io.OutputStream;

public final class IncrementalMacOutputStream extends OutputStream {
    private final long incrementalMac;
    private final OutputStream digestStream;
    private final OutputStream inner;
    private boolean closed = false;

    public IncrementalMacOutputStream(OutputStream inner, byte[] key, ChunkSizeChoice sizeChoice, OutputStream digestStream) {
        int chunkSize = sizeChoice.getSizeInBytes();
        this.incrementalMac = Native.IncrementalMac_Initialize(key, chunkSize);
        this.inner = inner;
        this.digestStream = digestStream;
    }

    @Override
    public void write(byte[] buffer) throws IOException {
        this.inner.write(buffer);
        byte[] digestIncrement = Native.IncrementalMac_Update(this.incrementalMac, buffer, 0, buffer.length);
        digestStream.write(digestIncrement);
    }

    @Override
    public void write(byte[] buffer, int offset, int length) throws IOException {
        this.inner.write(buffer, offset, length);
        byte[] digestIncrement = Native.IncrementalMac_Update(this.incrementalMac, buffer, offset, length);
        digestStream.write(digestIncrement);
    }

    @Override
    public void write(int b) throws IOException {
        // According to the spec the narrowing conversion to byte is expected here
        byte[] bytes = {(byte) b};
        byte[] digestIncrement = Native.IncrementalMac_Update(this.incrementalMac, bytes, 0, 1);
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
        try {
            flush();
        } catch (IOException ignored) {
        }
        byte[] digestIncrement = Native.IncrementalMac_Finalize(this.incrementalMac);
        digestStream.write(digestIncrement);
        Native.IncrementalMac_Destroy(this.incrementalMac);
        this.inner.close();
        this.digestStream.close();
        this.closed = true;
    }
}

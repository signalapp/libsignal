//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.incrementalmac;

import org.signal.libsignal.internal.Native;

import java.io.IOException;
import java.io.InputStream;

public final class IncrementalMacInputStream extends InputStream {
    private final long validatingMac;

    private final InputStream inner;
    private boolean closed = false;

    public IncrementalMacInputStream(InputStream inner, byte[] key, ChunkSizeChoice sizeChoice, byte[] digest) {
        int chunkSize = sizeChoice.getSizeInBytes();
        this.validatingMac = Native.ValidatingMac_Initialize(key, chunkSize, digest);
        this.inner = inner;
    }

    @Override
    public int read() throws IOException {
        int read = this.inner.read();
        // Narrowing conversion to byte is expected and intentional
        byte[] bytes = {(byte) read};
        int bytesLength = (read == -1) ? -1 : 1;
        return handleRead(bytes, 0, bytesLength);
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        int read = this.inner.read(bytes, offset, length);
        return handleRead(bytes, offset, read);
    }

    private int handleRead(byte[] bytes, int offset, int read) throws IOException {
        boolean isValid = (read == -1) ? Native.ValidatingMac_Finalize(this.validatingMac) : Native.ValidatingMac_Update(this.validatingMac, bytes, offset, read);
        if (!isValid) {
            throw new InvalidMacException();
        }
        return read;
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
}

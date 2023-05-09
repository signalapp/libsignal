//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.incrementalmac;

import org.signal.libsignal.internal.Native;

public abstract class ChunkSizeChoice {

    public abstract int getSizeInBytes();

    public static ChunkSizeChoice everyNthByte(int n) {
        return new EveryN(n);
    }

    public static ChunkSizeChoice inferChunkSize(int dataSize) {
        return new ChunksOf(dataSize);
    }

    private static final class EveryN extends ChunkSizeChoice {
        private int n;

        private EveryN(int n) {
            this.n = n;
        }

        public int getSizeInBytes() {
            return this.n;
        }
    }

    private static final class ChunksOf extends ChunkSizeChoice {
        private int dataSize;

        private ChunksOf(int dataSize) {
            this.dataSize = dataSize;
        }

        public int getSizeInBytes() {
            return Native.IncrementalMac_CalculateChunkSize(this.dataSize);
        }
    }
}

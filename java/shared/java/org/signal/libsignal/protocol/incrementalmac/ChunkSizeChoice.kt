//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.protocol.incrementalmac

import org.signal.libsignal.internal.Native

abstract class ChunkSizeChoice {
  abstract val sizeInBytes: Int
  companion object {
    @JvmStatic
    public fun everyNthByte(n: Int): ChunkSizeChoice {
      return EveryN(n)
    }

    @JvmStatic
    public fun inferChunkSize(dataSize: Int): ChunkSizeChoice {
      return ChunksOf(dataSize)
    }
  }
}

internal final data class EveryN(val n: Int) : ChunkSizeChoice() {
  override val sizeInBytes: Int = n
}

internal final data class ChunksOf(val dataSize: Int) : ChunkSizeChoice() {
  override val sizeInBytes: Int = Native.IncrementalMac_CalculateChunkSize(this.dataSize)
}

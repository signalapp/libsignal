//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import java.io.InputStream
import java.nio.ByteBuffer

/** Helpers for working with varint-length-delimited protobuf streams in tests. */
object VarintDelimitedTestUtil {
  /**
   * Reads a varint from [input], or returns -1 on EOF. Only supports up to two-byte varints.
   */
  @JvmStatic
  fun readVarint(input: InputStream): Int {
    val first = input.read()
    if (first == -1) return -1
    if (first < 0x80) return first
    val second = input.read()
    assertFalse("unexpected EOF in middle of varint", second == -1)
    assertTrue("at most a two-byte varint", second < 0x80)
    return (first - 0x80) or (second shl 7)
  }

  // Tiny varint parser, only supports two bytes.
  @JvmStatic
  fun readVarint(buf: ByteBuffer): Int {
    val first = buf.get().toInt() and 0xFF
    if (first < 0x80) return first
    val second = buf.get().toInt() and 0xFF
    assertTrue("at most a two-byte varint", second < 0x80)
    return (first - 0x80) or (second shl 7)
  }

  @JvmStatic
  fun chunkLengthDelimited(data: ByteArray): List<ByteArray> {
    val buf = ByteBuffer.wrap(data)
    val chunks = mutableListOf<ByteArray>()
    while (buf.hasRemaining()) {
      val start = buf.position()
      val length = readVarint(buf)
      val end = buf.position() + length
      buf.position(end)
      chunks.add(data.copyOfRange(start, end))
    }
    return chunks
  }

  @JvmStatic
  fun stripLengthPrefix(chunk: ByteArray): ByteArray {
    val buf = ByteBuffer.wrap(chunk)
    val length = readVarint(buf)
    return chunk.copyOfRange(buf.position(), buf.position() + length)
  }

  @JvmStatic
  fun insertLengthPrefix(data: ByteArray): ByteArray {
    assertTrue("test frame too large for single-byte varint", data.size < 0x80)
    return byteArrayOf(data.size.toByte()) + data
  }
}

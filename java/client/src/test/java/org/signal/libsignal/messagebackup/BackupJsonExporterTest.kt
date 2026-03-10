//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.util.ResourceReader
import java.io.ByteArrayOutputStream

class BackupJsonExporterTest {
  companion object {
    private fun chunkLengthDelimited(data: ByteArray) = VarintDelimitedTestUtil.chunkLengthDelimited(data)

    private fun stripLengthPrefix(chunk: ByteArray) = VarintDelimitedTestUtil.stripLengthPrefix(chunk)

    private fun insertLengthPrefix(data: ByteArray) = VarintDelimitedTestUtil.insertLengthPrefix(data)

    private fun concatFrames(frames: List<ByteArray>): ByteArray =
      frames.fold(ByteArrayOutputStream()) { out, frame -> out.apply { write(frame) } }.toByteArray()

    private val canonicalBackup: ByteArray by lazy {
      ResourceReader.readAll(
        BackupJsonExporterTest::class.java.getResourceAsStream("canonical-backup.binproto"),
      )
    }
    private val allChunks by lazy { chunkLengthDelimited(canonicalBackup) }
    private val backupInfo by lazy { stripLengthPrefix(allChunks.first()) }
    private val frameChunks by lazy { allChunks.drop(1) }

    // Disappearing chat item frame. Regenerate with:
    // % protoc rust/message-backup/src/proto/backup.proto \
    //     --encode signal.backup.Frame <<'PROTO' | base64
    // chatItem: { chatId: 1  authorId: 2  dateSent: 3  expiresInMs: 1 }
    // PROTO
    private val disappearingChatItemFrame: ByteArray =
      java.util.Base64
        .getDecoder()
        .decode("IggIARACGAMoAQ==")

    // View-once chat item frame with revisions. Regenerate with:
    // % protoc rust/message-backup/src/proto/backup.proto \
    //     --encode signal.backup.Frame <<'PROTO' | base64
    // chatItem: {
    //   chatId: 10  authorId: 11  dateSent: 12
    //   viewOnceMessage: { attachment: { wasDownloaded: true } }
    //   revisions: [{ chatId: 10  authorId: 11  dateSent: 9
    //     viewOnceMessage: { attachment: { wasDownloaded: true } } }]
    // }
    // PROTO
    private val viewOnceChatItemFrame: ByteArray =
      java.util.Base64
        .getDecoder()
        .decode("IhwIChALGAwyDQgKEAsYCZIBBAoCGAGSAQQKAhgB")
  }

  @Test
  fun streamsJsonLinesForCanonicalBackup() {
    val (exporter, initialChunk) = BackupJsonExporter.start(backupInfo)
    exporter.use {
      val chunkGroups =
        listOf(frameChunks.take(2), frameChunks.drop(2)).filter { it.isNotEmpty() }
      val exportedLines =
        chunkGroups.flatMap { exporter.exportFrames(concatFrames(it)) }.map {
          assertNotNull("canonical backup should produce a line", it.line)
          assertNull("canonical backup should validate cleanly", it.errorMessage)
          it.line!!
        }
      assertNull("canonical backup should validate cleanly", exporter.finishExport())

      val allLines = listOf(initialChunk) + exportedLines
      assertEquals(frameChunks.size + 1, allLines.size)
      for (line in allLines) {
        assertFalse("each line should be a single line", line.contains('\n'))
      }

      assertTrue(allLines[0].startsWith("{"))
      assertTrue(allLines[0].contains("\"version\""))
      assertTrue(allLines[1].contains("\"account\""))
    }
  }

  @Test
  fun returnsEmptyListWhenNoFramesProvided() {
    val (exporter, initialChunk) = BackupJsonExporter.start(backupInfo, validate = false)
    exporter.use {
      assertTrue(initialChunk.contains("\"version\""))
      assertEquals(emptyList<FrameExportResult>(), exporter.exportFrames(ByteArray(0)))
      assertNull(exporter.finishExport())
    }
  }

  @Test
  fun filtersDisappearingMessages() {
    val (exporter, _) = BackupJsonExporter.start(backupInfo, validate = false)
    exporter.use {
      val results = exporter.exportFrames(insertLengthPrefix(disappearingChatItemFrame))
      assertEquals(1, results.size)
      assertNull(results[0].line)
      assertNull(results[0].errorMessage)
      assertNull(exporter.finishExport())
    }
  }

  @Test
  fun filteredFramesHaveNoValidationErrorWhenValid() {
    val (exporter, _) = BackupJsonExporter.start(backupInfo, validate = true)
    exporter.use {
      val results = exporter.exportFrames(insertLengthPrefix(disappearingChatItemFrame))
      assertEquals(1, results.size)
      assertNull(results[0].line)
      assertNull(results[0].errorMessage)
      // Finish should report an error because we never sent an AccountData frame.
      assertNotNull(exporter.finishExport())
    }
  }

  @Test
  fun stripsAttachmentsFromViewOnceMessages() {
    val (exporter, _) = BackupJsonExporter.start(backupInfo, validate = false)
    exporter.use {
      val results = exporter.exportFrames(insertLengthPrefix(viewOnceChatItemFrame))
      assertEquals(1, results.size)
      assertNotNull(results[0].line)
      assertNull(results[0].errorMessage)

      val line = results[0].line!!
      assertTrue("should contain viewOnceMessage", line.contains("\"viewOnceMessage\""))
      assertFalse("attachment should be stripped", line.contains("\"wasDownloaded\""))
      assertNull(exporter.finishExport())
    }
  }

  @Test
  fun validatesFramesWhenRequested() {
    val (exporter, _) = BackupJsonExporter.start(backupInfo, validate = true)
    exporter.use {
      for (group in listOf(frameChunks.take(1), frameChunks.drop(1)).filter { it.isNotEmpty() }) {
        for (result in exporter.exportFrames(concatFrames(group))) {
          assertNotNull(result.line)
          assertNull(result.errorMessage)
        }
      }
      assertNull(exporter.finishExport())
    }
  }

  @Test
  fun finishReportsErrorWhenValidationFails() {
    val (exporter, initialChunk) = BackupJsonExporter.start(backupInfo, validate = true)
    exporter.use {
      assertTrue(initialChunk.startsWith("{"))
      // Skip the first frame (AccountData) to trigger a validation failure.
      exporter.exportFrames(concatFrames(frameChunks.drop(1)))
      val finishError = exporter.finishExport()
      assertNotNull(finishError)
      assertTrue(finishError!!.isNotEmpty())
    }
  }

  @Test
  fun canSkipValidation() {
    val (exporter, _) = BackupJsonExporter.start(backupInfo, validate = false)
    exporter.use {
      val results = exporter.exportFrames(concatFrames(frameChunks.drop(1)))
      for (result in results) {
        assertNull(result.errorMessage)
      }
      assertNull(exporter.finishExport())
    }
  }

  @Test(expected = ValidationError::class)
  fun rejectsMalformedDataEvenWithoutValidation() {
    val (exporter, _) = BackupJsonExporter.start(backupInfo, validate = false)
    exporter.use {
      exporter.exportFrames(byteArrayOf(0x02, 0x01))
    }
  }
}

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard

/**
 * Result of exporting a single backup frame to JSON.
 *
 * @property line The JSON line for this frame, or null if the frame was filtered out (e.g.
 *   disappearing messages).
 * @property errorMessage A validation error message, or null if the frame validated cleanly.
 */
public data class FrameExportResult(
  val line: String?,
  val errorMessage: String?,
)

/**
 * Exports a backup to newline-delimited JSON (JSONL), frame by frame.
 *
 * Optionally validates each frame and the whole backup during export. Sanitization (filtering
 * disappearing messages, stripping view-once attachments) is always applied.
 *
 * This class is not thread-safe.
 *
 * Example:
 * ```
 * val (exporter, initialChunk) = BackupJsonExporter.start(backupInfoBytes)
 * exporter.use {
 *     output.write(initialChunk)
 *     output.write("\n")
 *     while (hasMoreFrames) {
 *         val results = exporter.exportFrames(framedBytes)
 *         for (result in results) {
 *             result.line?.let { output.write(it); output.write("\n") }
 *             result.errorMessage?.let { log.warn(it) }
 *         }
 *     }
 *     val finishError = exporter.finishExport()
 *     finishError?.let { log.warn(it) }
 * }
 * ```
 */
public class BackupJsonExporter private constructor(
  private val handleOwner: NativeHandleGuard.CloseableOwner,
) : AutoCloseable {
  private var closed = false

  public companion object {
    /**
     * Creates a new exporter from serialized BackupInfo protobuf bytes.
     *
     * @param backupInfo serialized BackupInfo protobuf (without varint length prefix)
     * @param validate whether to run semantic validation during export (default true)
     * @return a pair of the exporter and the initial JSON chunk (serialized BackupInfo);
     *   caller must [close] the exporter when done
     * @throws ValidationError if the BackupInfo is malformed
     */
    @JvmStatic
    @JvmOverloads
    @Throws(ValidationError::class)
    public fun start(
      backupInfo: ByteArray,
      validate: Boolean = true,
    ): Pair<BackupJsonExporter, String> {
      val owner =
        object : NativeHandleGuard.CloseableOwner(
          Native.BackupJsonExporter_New(backupInfo, validate),
        ) {
          override fun release(nativeHandle: Long) {
            Native.BackupJsonExporter_Destroy(nativeHandle)
          }
        }
      val initialChunk =
        owner.guardedMap { h ->
          Native.BackupJsonExporter_GetInitialChunk(h)
        }
      return Pair(BackupJsonExporter(owner), initialChunk)
    }
  }

  /**
   * Exports one or more varint-delimited Frame protobuf messages to JSON lines.
   *
   * Can be called repeatedly to stream frames through the exporter.
   *
   * @param frames one or more varint-delimited serialized Frame protobufs
   * @return one result per frame, in order
   * @throws ValidationError if the frame bytes cannot be parsed at all
   * @throws IllegalStateException if the exporter has already been closed
   */
  @Throws(ValidationError::class)
  public fun exportFrames(frames: ByteArray): List<FrameExportResult> {
    check(!closed) { "BackupJsonExporter is already closed" }
    @Suppress("UNCHECKED_CAST")
    val pairs =
      handleOwner.guardedMapChecked { h -> Native.BackupJsonExporter_ExportFrames(h, frames) }
        as Array<Pair<String?, String?>>
    return pairs.map { (line, errorMessage) -> FrameExportResult(line, errorMessage) }
  }

  /**
   * Completes the export and runs any final whole-backup validation checks.
   *
   * Must be called before [close]. Calling this on a closed exporter throws
   * [IllegalStateException].
   *
   * @return a validation error message if whole-backup checks failed, or null if clean
   * @throws IllegalStateException if the exporter has already been closed
   */
  public fun finishExport(): String? {
    check(!closed) { "BackupJsonExporter is already closed" }
    return try {
      handleOwner.guardedRunChecked { h -> Native.BackupJsonExporter_Finish(h) }
      null
    } catch (e: ValidationError) {
      // All of our ValidationError instances should have a message, but we'll be defensive
      // and provide a default message if one is not available.
      e.message ?: "Backup export validation failed for unknown reason"
    }
  }

  /** Closes the exporter, releasing native resources. Safe to call multiple times. */
  override fun close() {
    closed = true
    handleOwner.close()
  }
}

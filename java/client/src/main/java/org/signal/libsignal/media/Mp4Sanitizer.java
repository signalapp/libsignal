//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.io.IOException;
import java.io.InputStream;
import org.signal.libsignal.internal.Native;

/**
 * An MP4 format “sanitizer”.
 *
 * <p>Currently the sanitizer always performs the following functions:
 *
 * <ul>
 *   <li>Return all presentation metadata present in the input as a self-contained contiguous byte
 *       array.
 *   <li>Find and return a pointer to the span in the input containing the (contiguous) media data.
 * </ul>
 *
 * <p>“Presentation” metadata means any metadata which is required by an MP4 player to play the
 * file. “Self-contained and contiguous” means that the returned metadata can be concatenated with
 * the media data to form a valid MP4 file.
 *
 * <p>The original metadata may or may not need to be modified in order to perform these functions.
 * In the case that the original metadata does not need to be modified, the returned sanitized
 * metadata will be null to prevent needless data copying.
 *
 * <h2>Unsupported MP4 features</h2>
 *
 * The sanitizer does not currently support:
 *
 * <ul>
 *   <li>“Fragmented” MP4 files, which are mostly used for adaptive-bitrate streaming.
 *   <li>Discontiguous media data, i.e. media data (mdat) boxes interspersed with presentation
 *       metadata (moov).
 *   <li>Media data references (dref) pointing to separate files.
 *   <li>Any similar format, e.g. Quicktime File Format (mov) or the legacy MP4 version 1, which
 *       does not contain the "isom" compatible brand in its file type header (ftyp).
 * </ul>
 */
public class Mp4Sanitizer {

  /**
   * Sanitize an MP4 input.
   *
   * <p>It's recommended that the given {@link InputStream} be capable of {@code skip}ping, and that
   * it skips fewer bytes than requested only when the end of stream is reached.
   *
   * @param input An MP4 format input stream.
   * @param length The exact length of the input stream.
   * @return The sanitized metadata.
   * @throws IOException If an IO error on the input occurs.
   * @throws ParseException If the input could not be parsed.
   */
  public static SanitizedMetadata sanitize(InputStream input, long length)
      throws IOException, ParseException {
    long sanitizedMetadataHandle =
        filterExceptions(
            IOException.class,
            ParseException.class,
            () -> Native.Mp4Sanitizer_Sanitize(TrustedSkipInputStream.makeTrusted(input), length));
    try {
      byte[] sanitizedMetadata = Native.SanitizedMetadata_GetMetadata(sanitizedMetadataHandle);
      if (sanitizedMetadata.length == 0) {
        sanitizedMetadata = null;
      }
      long dataOffset = Native.SanitizedMetadata_GetDataOffset(sanitizedMetadataHandle);
      long dataLength = Native.SanitizedMetadata_GetDataLen(sanitizedMetadataHandle);
      return new SanitizedMetadata(sanitizedMetadata, dataOffset, dataLength);
    } finally {
      Native.SanitizedMetadata_Destroy(sanitizedMetadataHandle);
    }
  }

  /**
   * Sanitize an MP4 input featuring multiple MDAT boxes compounded to a single cumulative MDAT box
   * whose byte length needs to be passed down to MP4 sanitizer
   *
   * <p>It's recommended that the given {@link InputStream} be capable of {@code skip}ping, and that
   * it skips fewer bytes than requested only when the end of stream is reached.
   *
   * @param input An MP4 format input stream.
   * @param length The exact length of the input stream.
   * @param cumulativeMdatBoxSize The byte length of cumulative, compounded MDAT box
   * @return The sanitized metadata.
   * @throws IOException If an IO error on the input occurs.
   * @throws ParseException If the input could not be parsed.
   */
  public static SanitizedMetadata sanitizeFileWithCompoundedMdatBoxes(
      InputStream input, long length, int cumulativeMdatBoxSize)
      throws IOException, ParseException {
    long sanitizedMetadataHandle =
        filterExceptions(
            IOException.class,
            ParseException.class,
            () ->
                Native.Mp4Sanitizer_Sanitize_File_With_Compounded_MDAT_Boxes(
                    TrustedSkipInputStream.makeTrusted(input), length, cumulativeMdatBoxSize));
    try {
      byte[] sanitizedMetadata = Native.SanitizedMetadata_GetMetadata(sanitizedMetadataHandle);
      if (sanitizedMetadata.length == 0) {
        sanitizedMetadata = null;
      }
      long dataOffset = Native.SanitizedMetadata_GetDataOffset(sanitizedMetadataHandle);
      long dataLength = Native.SanitizedMetadata_GetDataLen(sanitizedMetadataHandle);
      return new SanitizedMetadata(sanitizedMetadata, dataOffset, dataLength);
    } finally {
      Native.SanitizedMetadata_Destroy(sanitizedMetadataHandle);
    }
  }
}

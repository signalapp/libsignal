//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import org.signal.libsignal.internal.Native;

import java.io.IOException;
import java.io.InputStream;

/**
 * An MP4 format “sanitizer”.
 *
 * Currently the sanitizer always performs the following functions:
 *
 * <ul>
 *     <li>Return all presentation metadata present in the input as a self-contained contiguous byte array.</li>
 *     <li>Find and return a pointer to the span in the input containing the (contiguous) media data.</li>
 * </ul>
 *
 * <p> “Presentation” metadata means any metadata which is required by an MP4 player to play the file. “Self-contained and contiguous” means
 * that the returned metadata can be concatenated with the media data to form a valid MP4 file.
 *
 * <p> The original metadata may or may not need to be modified in order to perform these functions. In the case that the original metadata does
 * not need to be modified, the returned sanitized metadata will be null to prevent needless data copying.
 *
 * <h2>Unsupported MP4 features</h2>
 *
 * The sanitizer does not currently support:
 *
 * <ul>
 *     <li>“Fragmented” MP4 files, which are mostly used for adaptive-bitrate streaming.</li>
 *     <li>Discontiguous media data, i.e. media data (mdat) boxes interspersed with presentation metadata (moov).</li>
 *     <li>Media data references (dref) pointing to separate files.</li>
 *     <li>Any similar format, e.g. Quicktime File Format (mov) or the legacy MP4 version 1, which does not contain the "isom" compatible
 *         brand in its file type header (ftyp).</li>
 * </ul>
 */
public class Mp4Sanitizer {

    /**
     * Sanitize an MP4 input.
     *
     * <p> It's recommended that the given {@link InputStream} be capable of {@code skip}ping. If it is, then it <i>must</i> only skip fewer
     * bytes than requested when the end of stream is reached.
     *
     * @param input An MP4 format input stream.
     * @param length The exact length of the input stream.
     * @return The sanitized metadata.
     * @throws IOException If an IO error on the input occurs.
     * @throws ParseException If the input could not be parsed.
     */
    public static SanitizedMetadata sanitize(InputStream input, long length) throws IOException, ParseException {
        long sanitizedMetadataHandle = Native.Mp4Sanitizer_Sanitize(input, length);
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

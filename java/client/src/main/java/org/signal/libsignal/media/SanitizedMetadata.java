//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

public class SanitizedMetadata {

    private byte[] sanitizedMetadata;
    private long dataOffset;
    private long dataLength;

    public SanitizedMetadata(byte[] sanitizedMetadata, long dataOffset, long dataLength) {
        this.sanitizedMetadata = sanitizedMetadata;
        this.dataOffset = dataOffset;
        this.dataLength = dataLength;
    }

    /**
     * Get the sanitized metadata, if any.
     * @return The sanitized metadata, or {@code null} if it didn't need to be sanitized.
     */
    public byte[] getSanitizedMetadata() {
        return sanitizedMetadata;
    }

    /**
     * Get the offset of the media data in the processed input.
     * @return The offset of the media data in the processed input.
     */
    public long getDataOffset() {
        return dataOffset;
    }

    /**
     * Get the length of the media data in the processed input.
     * @return The length of the media data in the processed input.
     */
    public long getDataLength() {
        return dataLength;
    }
}

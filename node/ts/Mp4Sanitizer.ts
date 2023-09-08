//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * An MP4 format “sanitizer”.
 *
 * Currently the sanitizer always performs the following functions:
 *
 * - Return all presentation metadata present in the input as a self-contained contiguous byte array.
 * - Find and return a pointer to the span in the input containing the (contiguous) media data.
 *
 * “Presentation” metadata means any metadata which is required by an MP4 player to play the file. “Self-contained and
 * contiguous” means that the returned metadata can be concatenated with the media data to form a valid MP4 file.
 *
 * The original metadata may or may not need to be modified in order to perform these functions. In the case that the
 * original metadata does not need to be modified, the returned sanitized metadata will be null to prevent needless data
 * copying.
 *
 * ## Unsupported MP4 features
 *
 * The sanitizer does not currently support:
 *
 * - “Fragmented” MP4 files, which are mostly used for adaptive-bitrate streaming.
 * - Discontiguous media data, i.e. media data (mdat) boxes interspersed with presentation metadata (moov).
 * - Media data references (dref) pointing to separate files.
 * - Any similar format, e.g. Quicktime File Format (mov) or the legacy MP4 version 1, which does not contain the "isom"
 *   compatible brand in its file type header (ftyp).
 *
 * @module Mp4Sanitizer
 */

import * as Native from '../Native';
import { InputStream } from './io';
import { bufferFromBigUInt64BE } from './zkgroup/internal/BigIntUtil';

export class SanitizedMetadata {
  readonly _nativeHandle: Native.SanitizedMetadata;

  private constructor(handle: Native.SanitizedMetadata) {
    this._nativeHandle = handle;
  }

  static _fromNativeHandle(
    handle: Native.SanitizedMetadata
  ): SanitizedMetadata {
    return new SanitizedMetadata(handle);
  }

  /**
   * Get the sanitized metadata, if any.
   * @return The sanitized metadata, or {@code null} if it didn't need to be sanitized.
   */
  getMetadata(): Buffer | null {
    const metadata = Native.SanitizedMetadata_GetMetadata(this);
    if (metadata.length == 0) {
      return null;
    }
    return metadata;
  }

  /**
   * Get the offset of the media data in the processed input.
   * @return The offset of the media data in the processed input.
   */
  getDataOffset(): bigint {
    const buffer = Native.SanitizedMetadata_GetDataOffset(this);
    return buffer.readBigUInt64BE();
  }

  /**
   * Get the length of the media data in the processed input.
   * @return The length of the media data in the processed input.
   */
  getDataLen(): bigint {
    const buffer = Native.SanitizedMetadata_GetDataLen(this);
    return buffer.readBigUInt64BE();
  }
}

/**
 * Sanitize an MP4 input.
 *
 * @param input An MP4 format input stream.
 * @param length The exact length of the input stream.
 * @return The sanitized metadata.
 * @throws IoError If an IO error on the input occurs.
 * @throws InvalidMediaInputError If the input could not be parsed because it was invalid.
 * @throws UnsupportedMediaInputError If the input could not be parsed because it's unsupported in some way.
 */
export async function sanitize(
  input: InputStream,
  len: bigint
): Promise<SanitizedMetadata> {
  const sanitizedMetadataNativeHandle = await Native.Mp4Sanitizer_Sanitize(
    input,
    bufferFromBigUInt64BE(len)
  );
  return SanitizedMetadata._fromNativeHandle(sanitizedMetadataNativeHandle);
}

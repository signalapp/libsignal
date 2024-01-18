//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * A WebP format “sanitizer”.
 *
 * The sanitizer currently simply checks the validity of a WebP file input, so that passing a malformed file to an
 * unsafe parser can be avoided.
 *
 * @module WebpSanitizer
 */

import * as Native from '../Native';

/**
 * Sanitize a WebP input.
 *
 * @param input A WebP format input stream.
 * @param length The exact length of the input stream.
 * @throws IoError If an IO error on the input occurs.
 * @throws InvalidMediaInputError If the input could not be parsed because it was invalid.
 * @throws UnsupportedMediaInputError If the input could not be parsed because it's unsupported in some way.
 */
export function sanitize(input: Buffer): void {
  Native.WebpSanitizer_Sanitize(input);
}

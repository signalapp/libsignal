//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import java.io.IOException;
import java.io.InputStream;
import org.signal.libsignal.internal.Native;

/**
 * A WebP format “sanitizer”.
 *
 * <p>The sanitizer currently simply checks the validity of a WebP file input, so that passing a
 * malformed file to an unsafe parser can be avoided.
 */
public class WebpSanitizer {

  /**
   * Sanitize a WebP input.
   *
   * <p>It's recommended that the given {@link InputStream} be capable of {@code skip}ping. If it
   * is, then it <i>must</i> only skip fewer bytes than requested when the end of stream is reached.
   *
   * @param input A WebP format input stream.
   * @param length The exact length of the input stream.
   * @throws IOException If an IO error on the input occurs.
   * @throws ParseException If the input could not be parsed.
   */
  public static void sanitize(InputStream input, long length) throws IOException, ParseException {
    Native.WebpSanitizer_Sanitize(input, length);
  }
}

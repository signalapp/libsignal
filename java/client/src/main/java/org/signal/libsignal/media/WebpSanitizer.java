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
 * A WebP format “sanitizer”.
 *
 * <p>The sanitizer currently simply checks the validity of a WebP file input, so that passing a
 * malformed file to an unsafe parser can be avoided.
 */
public class WebpSanitizer {

  /**
   * Sanitize a WebP input.
   *
   * <p>It's recommended that the given {@link InputStream} be capable of {@code skip}ping, and that
   * it skips fewer bytes than requested only when the end of stream is reached.
   *
   * @param input A WebP format input stream.
   * @throws IOException If an IO error on the input occurs.
   * @throws ParseException If the input could not be parsed.
   */
  public static void sanitize(InputStream input) throws IOException, ParseException {
    filterExceptions(
        IOException.class,
        ParseException.class,
        () -> Native.WebpSanitizer_Sanitize(TrustedSkipInputStream.makeTrusted(input)));
  }

  /**
   * Sanitize a WebP input.
   *
   * @deprecated Prefer the version without a length; it is now ignored.
   */
  @Deprecated
  public static void sanitize(InputStream input, long ignoredLength)
      throws IOException, ParseException {
    sanitize(input);
  }
}

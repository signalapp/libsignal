//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import java.io.IOException;
import java.io.InputStream;

/**
 * Implemented by InputStreams that guarantee that their {@code skip} methods always skip the full
 * amount unless EOF is reached (or an exception is thrown).
 */
public interface TrustedSkipInputStream {
  /**
   * @see InputStream#skip
   */
  public long skip(final long amount) throws IOException;

  /**
   * Wraps {@code inputStream} such that it has a trusted {@code skip} method, unless it already
   * implements TrustedSkipInputStream.
   */
  public static InputStream makeTrusted(InputStream inputStream) {
    if (inputStream instanceof TrustedSkipInputStream) {
      return inputStream;
    }
    return new GuaranteedSkipInputStream(inputStream);
  }
}

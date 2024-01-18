//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A wrapper around an InputStream that retries {@link #skip} calls until the full amount has been
 * skipped or EOF has been reached.
 *
 * <p>This may require using {@link #read} instead of {@link #skip}.
 */
/* package */ class GuaranteedSkipInputStream extends FilterInputStream
    implements TrustedSkipInputStream {

  /**
   * A buffer size large enough to allow reading in bulk, but not so large that it takes a
   * noticeable amount of memory.
   *
   * <p>The value comes from experiments by the Android team; larger buffers were not measurably
   * faster to do bulk reads, but smaller buffers were noticeably slower.
   */
  private static final int SKIP_BUFFER_SIZE = 2048;

  public GuaranteedSkipInputStream(InputStream in) {
    super(in);
  }

  @Override
  public long skip(final long amount) throws IOException {
    long remaining = amount;

    if (remaining <= 0) {
      return 0;
    }

    // First try to use skip(), which may be cheaper than reading.
    do {
      final long amountSkipped = super.skip(remaining);
      if (amountSkipped == 0) {
        break;
      }
      remaining -= amountSkipped;
    } while (remaining > 0);

    // But fall back to reading, which is guaranteed to block until at least one byte is read
    // (unless we actually reach EOF).
    if (remaining > 0) {
      final byte[] skipBuf = new byte[SKIP_BUFFER_SIZE];
      do {
        final long amountRead = this.read(skipBuf, 0, (int) Math.min(remaining, skipBuf.length));
        if (amountRead == -1) {
          break;
        }
        remaining -= amountRead;
      } while (remaining > 0);
    }

    return amount - remaining;
  }
}

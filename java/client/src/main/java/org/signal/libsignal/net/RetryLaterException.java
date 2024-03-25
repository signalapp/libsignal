//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.time.Duration;

public class RetryLaterException extends Exception {
  /** The amount of time to wait before retrying. */
  public final Duration duration;

  public RetryLaterException(long retryAfterSeconds) {
    this(Duration.ofSeconds(retryAfterSeconds));
  }

  private RetryLaterException(Duration duration) {
    super("Retry after " + duration.getSeconds() + " seconds");
    this.duration = duration;
  }
}

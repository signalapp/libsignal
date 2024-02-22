//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.time.Duration;

public abstract class DurationExt {
  public static final int timeoutMillis(Duration timeout) {
    int millis;
    try {
      millis = Math.toIntExact(timeout.toMillis());
    } catch (ArithmeticException e) {
      millis = Integer.MAX_VALUE;
    }
    return millis;
  }
}

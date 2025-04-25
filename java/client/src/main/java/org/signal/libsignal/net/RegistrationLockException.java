//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.time.Duration;
import org.signal.libsignal.internal.CalledFromNative;

public class RegistrationLockException extends RegistrationException {
  private Duration timeRemaining;
  private String svr2Username;
  private String svr2Password;

  @CalledFromNative
  private RegistrationLockException(
      long timeRemainingSeconds, String svr2Username, String svr2Password) {
    super("Registration lock is enabled");
    this.timeRemaining = Duration.ofSeconds(timeRemainingSeconds);
    this.svr2Username = svr2Username;
    this.svr2Password = svr2Password;
  }

  public Duration getTimeRemaining() {
    return this.timeRemaining;
  }

  public String getSvr2Username() {
    return this.svr2Username;
  }

  public String getSvr2Password() {
    return this.svr2Password;
  }

  @Override
  public String toString() {
    // Make sure we're not printing out the username or password.
    return super.toString();
  }
}

//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.svr;

public final class RestoreFailedException extends SvrException {
  private int triesRemaining;

  public RestoreFailedException(String message, int triesRemaining) {
    super(message);
    this.triesRemaining = triesRemaining;
  }

  public int getTriesRemaining() {
    return this.triesRemaining;
  }
}

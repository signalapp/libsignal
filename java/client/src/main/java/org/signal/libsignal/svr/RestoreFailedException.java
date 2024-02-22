//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.svr;

public final class RestoreFailedException extends SvrException {
  public RestoreFailedException(String message) {
    super(message);
  }
}

//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.svr;

public class InvalidSvrBDataException extends SvrException {
  public InvalidSvrBDataException(String message) {
    super(message);
  }

  public InvalidSvrBDataException(String message, Throwable cause) {
    super(message, cause);
  }
}

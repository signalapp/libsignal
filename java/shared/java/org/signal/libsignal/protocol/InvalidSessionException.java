//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

public class InvalidSessionException extends IllegalStateException {
  public InvalidSessionException(String detailMessage) {
    super(detailMessage);
  }

  public InvalidSessionException(String detailMessage, Throwable cause) {
    super(detailMessage, cause);
  }
}

//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

public class ReusedBaseKeyException extends InvalidMessageException {

  public ReusedBaseKeyException() {}

  public ReusedBaseKeyException(String detailMessage) {
    super(detailMessage);
  }

  public ReusedBaseKeyException(Throwable throwable) {
    super(throwable);
  }

  public ReusedBaseKeyException(String detailMessage, Throwable throwable) {
    super(detailMessage, throwable);
  }
}

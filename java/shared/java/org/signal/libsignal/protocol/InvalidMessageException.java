//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import java.util.List;

public class InvalidMessageException extends Exception {

  public InvalidMessageException() {}

  public InvalidMessageException(String detailMessage) {
    super(detailMessage);
  }

  public InvalidMessageException(Throwable throwable) {
    super(throwable);
  }

  public InvalidMessageException(String detailMessage, Throwable throwable) {
    super(detailMessage, throwable);
  }

  public InvalidMessageException(String detailMessage, List<Exception> exceptions) {
    super(detailMessage, exceptions.get(0));
  }
}

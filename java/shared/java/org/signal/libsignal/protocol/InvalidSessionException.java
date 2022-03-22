/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol;

public class InvalidSessionException extends IllegalStateException {
  public InvalidSessionException(String detailMessage) {
    super(detailMessage);
  }
}

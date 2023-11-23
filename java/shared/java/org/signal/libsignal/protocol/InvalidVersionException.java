//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

public class InvalidVersionException extends Exception {
  public InvalidVersionException(String detailMessage) {
    super(detailMessage);
  }
}

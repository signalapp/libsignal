//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

public class DuplicateMessageException extends Exception {
  public DuplicateMessageException(String s) {
    super(s);
  }
}

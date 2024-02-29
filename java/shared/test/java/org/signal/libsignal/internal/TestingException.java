//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

public class TestingException extends Exception {
  public TestingException(String message) {
    super(message);
  }
}

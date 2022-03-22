//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

public class InvalidInputException extends Exception {

  public InvalidInputException() {

  }

  public InvalidInputException(String message) {
    super(message);
  }

}

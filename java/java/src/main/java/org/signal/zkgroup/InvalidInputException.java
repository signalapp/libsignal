//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

package org.signal.zkgroup;

public class InvalidInputException extends Exception {

  public InvalidInputException() {

  }

  public InvalidInputException(String message) {
    super(message);
  }

}

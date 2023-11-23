//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

public class InvalidRegistrationIdException extends Exception {

  private final SignalProtocolAddress address;

  public InvalidRegistrationIdException(SignalProtocolAddress address, String message) {
    super(message);
    this.address = address;
  }

  public SignalProtocolAddress getAddress() {
    return address;
  }
}

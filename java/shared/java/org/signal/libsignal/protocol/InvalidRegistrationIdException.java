/**
 * Copyright (C) 2021 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
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

/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol;

public class NoSessionException extends Exception {
  private final SignalProtocolAddress address;

  public NoSessionException(String message) {
    this(null, message);
  }

  public NoSessionException(SignalProtocolAddress address, String message) {
    super(message);
    this.address = address;
  }

  public SignalProtocolAddress getAddress() {
    return address;
  }
}

//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

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

/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.logging;

public class SignalProtocolLoggerProvider {

  private static SignalProtocolLogger provider;

  public static SignalProtocolLogger getProvider() {
    return provider;
  }

  public static void setProvider(SignalProtocolLogger provider) {
    SignalProtocolLoggerProvider.provider = provider;
  }
}

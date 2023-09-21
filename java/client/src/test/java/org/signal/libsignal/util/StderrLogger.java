//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.util;

import org.signal.libsignal.protocol.logging.SignalProtocolLogger;

public class StderrLogger implements SignalProtocolLogger {
  @Override
  public void log(int priority, String tag, String message) {
    String prefix;
    switch (priority) {
      case SignalProtocolLogger.VERBOSE:
        prefix = "V ";
        break;
      case SignalProtocolLogger.DEBUG:
        prefix = "D ";
        break;
      case SignalProtocolLogger.INFO:
        prefix = "I ";
        break;
      case SignalProtocolLogger.WARN:
        prefix = "W ";
        break;
      case SignalProtocolLogger.ERROR:
        prefix = "E ";
        break;
      case SignalProtocolLogger.ASSERT:
        prefix = "A ";
        break;
      default:
        prefix = "";
        break;
    }
    System.err.println(prefix + tag + ": " + message);
  }
}

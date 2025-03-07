//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.util;

import org.junit.rules.ExternalResource;
import org.signal.libsignal.protocol.logging.SignalProtocolLogger;
import org.signal.libsignal.protocol.logging.SignalProtocolLoggerProvider;

public class TestLogger extends ExternalResource {
  private static boolean loggerInitialized = false;

  private static synchronized void ensureLoggerInitialized() {
    if (loggerInitialized) {
      return;
    }
    loggerInitialized = true;

    // AndroidJUnitRunner sets up its own logging, so if that's available, we're done.
    try {
      Class.forName("org.signal.libsignal.util.AndroidJUnitRunner");
      return;
    } catch (ClassNotFoundException e) {
      // Okay, we're not running as an Android instrumented test.
    }

    SignalProtocolLoggerProvider.initializeLogging(SignalProtocolLogger.VERBOSE);
    SignalProtocolLoggerProvider.setProvider(
        new SignalProtocolLogger() {
          public void log(int priority, String tag, String message) {
            System.err.println(priority + " " + message);
          }
        });
  }

  @Override
  protected void before() throws Throwable {
    ensureLoggerInitialized();
  }
}

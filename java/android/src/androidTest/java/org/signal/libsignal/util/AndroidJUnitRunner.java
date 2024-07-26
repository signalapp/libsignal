//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.util;

import android.os.Bundle;
import org.signal.libsignal.protocol.logging.AndroidSignalProtocolLogger;
import org.signal.libsignal.protocol.logging.SignalProtocolLogger;
import org.signal.libsignal.protocol.logging.SignalProtocolLoggerProvider;

/** Custom setup for our JUnit tests, when run as instrumentation tests. */
public class AndroidJUnitRunner extends androidx.test.runner.AndroidJUnitRunner {
  @Override
  public void onCreate(Bundle bundle) {
    super.onCreate(bundle);

    // Make sure libsignal logs get caught correctly.
    SignalProtocolLoggerProvider.setProvider(new AndroidSignalProtocolLogger());
    SignalProtocolLoggerProvider.initializeLogging(SignalProtocolLogger.VERBOSE);

    // Propagate any "environment variables" the test might need into System properties.
    String testEnvironment = bundle.getString(TestEnvironment.PROPERTY_NAMESPACE);
    if (testEnvironment != null) {
      for (String joinedProp : testEnvironment.split(",")) {
        String[] splitProp = joinedProp.split("=", 2);
        if (splitProp.length != 2) {
          continue;
        }
        System.setProperty(TestEnvironment.PROPERTY_NAMESPACE + "." + splitProp[0], splitProp[1]);
      }
    }
  }
}

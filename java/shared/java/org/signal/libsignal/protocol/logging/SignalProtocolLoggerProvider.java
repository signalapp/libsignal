//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.logging;

import org.signal.libsignal.internal.Native;

public class SignalProtocolLoggerProvider {

  private static SignalProtocolLogger provider;

  /**
   * Enables logging from libsignal's native code.
   *
   * <p>Should only be called once; later calls will be ignored.
   *
   * @param maxLevel The most severe level that should be logged. Should be one of the constants
   *     from {@link SignalProtocolLogger}. In a normal release build, this is clamped to {@code
   *     INFO}.
   */
  public static void initializeLogging(int maxLevel) {
    if (maxLevel < SignalProtocolLogger.VERBOSE || maxLevel > SignalProtocolLogger.ASSERT) {
      throw new IllegalArgumentException("invalid log level");
    }
    Native.Logger_Initialize(maxLevel, Log.class);
  }

  public static SignalProtocolLogger getProvider() {
    return provider;
  }

  public static void setProvider(SignalProtocolLogger provider) {
    SignalProtocolLoggerProvider.provider = provider;
  }
}

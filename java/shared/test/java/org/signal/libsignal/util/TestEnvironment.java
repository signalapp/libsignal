//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.util;

public class TestEnvironment {
  public static final String PROPERTY_NAMESPACE = "org.signal.libsignal.test.environment";

  /**
   * Looks in the environment first, then in System properties, namespaced by {@link
   * #PROPERTY_NAMESPACE}.
   *
   * <p>The Android runner manually propagates environment variable into the namespaced system
   * properties.
   */
  public static String get(final String name) {
    final String result = System.getenv(name);
    if (result != null) {
      return result;
    }
    return System.getProperty(PROPERTY_NAMESPACE + "." + name);
  }
}

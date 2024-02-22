//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.util;

import java.security.SecureRandom;

/**
 * Helper class for generating keys of different types.
 *
 * @author Moxie Marlinspike
 */
public class KeyHelper {

  private KeyHelper() {}

  /**
   * Generate a registration ID. Clients should only do this once, at install time.
   *
   * @param extendedRange By default (false), the generated registration ID is sized to require the
   *     minimal possible protobuf encoding overhead. Specify true if the caller needs the full
   *     range of MAX_INT at the cost of slightly higher encoding overhead.
   * @return the generated registration ID.
   */
  public static int generateRegistrationId(boolean extendedRange) {
    SecureRandom secureRandom = new SecureRandom();
    if (extendedRange) return secureRandom.nextInt(Integer.MAX_VALUE - 1) + 1;
    else return secureRandom.nextInt(16380) + 1;
  }
}

/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.util;

import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

/**
 * Helper class for generating keys of different types.
 *
 * @author Moxie Marlinspike
 */
public class KeyHelper {

  private KeyHelper() {}

  /**
   * Generate a registration ID.  Clients should only do this once,
   * at install time.
   *
   * @param extendedRange By default (false), the generated registration
   *                      ID is sized to require the minimal possible protobuf
   *                      encoding overhead. Specify true if the caller needs
   *                      the full range of MAX_INT at the cost of slightly
   *                      higher encoding overhead.
   * @return the generated registration ID.
   */
  public static int generateRegistrationId(boolean extendedRange) {
    try {
      SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
      if (extendedRange) return secureRandom.nextInt(Integer.MAX_VALUE - 1) + 1;
      else               return secureRandom.nextInt(16380) + 1;
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

}

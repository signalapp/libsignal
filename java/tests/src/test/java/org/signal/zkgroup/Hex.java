//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

package org.signal.zkgroup;

import java.io.IOException;

/**
 * Utility for bytes to hex and hex to bytes.
 */
public final class Hex {

  private final static char[] HEX_DIGITS = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };

  private Hex() {
  }

  public static String toStringCondensed(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte aByte : bytes) {
      appendHexChar(builder, aByte);
    }
    return builder.toString();
  }

  public static byte[] fromStringCondensedAssert(String encoded) {
    try {
        return fromStringCondensed(encoded);
    } catch (IOException e) {
        throw new AssertionError(e);
    }
  }

  public static byte[] fromStringCondensed(String encoded) throws IOException {
    final char[] data = encoded.toCharArray();
    final int    len  = data.length;

    if ((len & 0x01) != 0) {
      throw new IOException("Odd number of characters.");
    }

    final byte[] out = new byte[len >> 1];

    for (int i = 0, j = 0; j < len; i++) {
      int f = Character.digit(data[j], 16) << 4;
      j++;
      f = f | Character.digit(data[j], 16);
      j++;
      out[i] = (byte) (f & 0xFF);
    }

    return out;
  }

  private static void appendHexChar(StringBuilder buf, int b) {
    buf.append(HEX_DIGITS[(b >> 4) & 0xf]);
    buf.append(HEX_DIGITS[b & 0xf]);
  }
}

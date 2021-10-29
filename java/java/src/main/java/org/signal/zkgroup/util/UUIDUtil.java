//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

package org.signal.zkgroup.util;

import java.util.UUID;

public final class UUIDUtil {

  public static final int UUID_LENGTH = 16;

  private UUIDUtil() {
  }

  public static UUID deserialize(byte[] bytes) {
    long mostSignificantBits  = bytesToLong(bytes, 0);
    long leastSignificantBits = bytesToLong(bytes, 8);

    return new UUID(mostSignificantBits, leastSignificantBits);
  }

  public static byte[] serialize(UUID uuid) {
    byte[] bytes = new byte[UUID_LENGTH];

    longToBytes(uuid.getMostSignificantBits(),  bytes, 0);
    longToBytes(uuid.getLeastSignificantBits(), bytes, 8);

    return bytes;
  }

  private static void longToBytes(long l, byte[] result, int offset) {
    for (int i = 7; i >= 0; i--) {
      result[i + offset] = (byte) (l & 0xFF);
      l >>= 8;
    }
  }

  private static long bytesToLong(byte[] b, int offset) {
    long result = 0;
    for (int i = 0; i < 8; i++) {
      result <<= 8;
      result |= (b[i + offset] & 0xFF);
    }
    return result;
  }
}

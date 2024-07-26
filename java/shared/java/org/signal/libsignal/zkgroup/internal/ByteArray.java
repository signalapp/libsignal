//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.internal;

import java.util.Arrays;
import java.util.Locale;
import org.signal.libsignal.zkgroup.InvalidInputException;

public abstract class ByteArray {

  /** Marker for ByteArray subclasses that want to skip validation. */
  public static enum UncheckedAndUncloned {
    UNCHECKED_AND_UNCLONED;
  }

  /** Marker for ByteArray subclasses that want to skip validation. */
  public static final UncheckedAndUncloned UNCHECKED_AND_UNCLONED =
      UncheckedAndUncloned.UNCHECKED_AND_UNCLONED;

  protected final byte[] contents;

  protected ByteArray(byte[] contents) {
    this.contents = contents.clone();
  }

  protected ByteArray(byte[] contents, UncheckedAndUncloned marker) {
    this.contents = contents;
  }

  protected ByteArray(byte[] contents, int expectedLength) throws InvalidInputException {
    this.contents = cloneArrayOfLength(contents, expectedLength);
  }

  private static byte[] cloneArrayOfLength(byte[] bytes, int expectedLength)
      throws InvalidInputException {
    if (bytes.length != expectedLength) {
      throw new InvalidInputException(
          String.format(
              Locale.US,
              "Length of array supplied was %d expected %d",
              bytes.length,
              expectedLength));
    }

    return bytes.clone();
  }

  public byte[] getInternalContentsForJNI() {
    return contents;
  }

  public byte[] serialize() {
    return contents.clone();
  }

  @Override
  public int hashCode() {
    return getClass().hashCode() * 31 + Arrays.hashCode(contents);
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) return false;

    ByteArray other = (ByteArray) o;
    return constantTimeEqual(contents, other.getInternalContentsForJNI());
  }

  public static boolean constantTimeEqual(byte[] lhs, byte[] rhs) {
    if (lhs == rhs) return true;

    if (lhs.length != rhs.length) return false;

    int result = 0;
    for (int i = 0; i < lhs.length; i++) {
      result |= lhs[i] ^ rhs[i];
    }
    return result == 0;
  }
}

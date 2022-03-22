//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.internal;

import org.signal.libsignal.zkgroup.InvalidInputException;

import java.util.Arrays;
import java.util.Locale;

public abstract class ByteArray {

  protected final byte[] contents;

  protected ByteArray(byte[] contents) {
    this.contents = contents.clone();
  }

  protected ByteArray(byte[] contents, int expectedLength) throws InvalidInputException {
    this.contents = cloneArrayOfLength(contents, expectedLength);
  }

  private static byte[] cloneArrayOfLength(byte[] bytes, int expectedLength) throws InvalidInputException {
    if (bytes.length != expectedLength) {
      throw new InvalidInputException(String.format(Locale.US, "Length of array supplied was %d expected %d", bytes.length, expectedLength));
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
    if (contents == other.getInternalContentsForJNI()) return true;

    if (contents.length != other.getInternalContentsForJNI().length) return false;

    int result = 0;
    for (int i = 0; i < contents.length; i++) {
      result |= contents[i] ^ other.getInternalContentsForJNI()[i];
    }
    return result == 0;
  }
}

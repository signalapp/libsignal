//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

package org.signal.zkgroup.internal;

import org.signal.zkgroup.InvalidInputException;

import java.util.Arrays;
import java.util.Locale;

public abstract class ByteArray {

  protected final byte[] contents;

  protected ByteArray(byte[] contents, int expectedLength) throws InvalidInputException {
    this.contents = cloneArrayOfLength(contents, expectedLength);
  }

  protected ByteArray(byte[] contents, int expectedLength, boolean unrecoverable) {
    try {
      this.contents = cloneArrayOfLength(contents, expectedLength);
    } catch (InvalidInputException e) {
      throw new IllegalArgumentException(e);
    }
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

  @Override
  public int hashCode() {
    return getClass().hashCode() * 31 + Arrays.hashCode(contents);
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) return false;

    ByteArray other = (ByteArray) o;
    if (contents == other.contents) return true;

    if (contents.length != other.contents.length) return false;

    int result = 0;
    for (int i = 0; i < contents.length; i++) {
      result |= contents[i] ^ other.contents[i];
    }
    return result == 0;
  }
}

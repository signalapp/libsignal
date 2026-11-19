//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.zkgroup.InvalidInputException;

public final class ProfileKeyVersion {

  private byte[] contents;

  @CalledFromNative
  public ProfileKeyVersion(byte[] contents) throws InvalidInputException {
    if (contents.length != 64) {
      throw new InvalidInputException("bad length");
    }
    this.contents = contents.clone();
  }

  public ProfileKeyVersion(String contents) throws InvalidInputException {
    this(contents.getBytes(StandardCharsets.UTF_8));
  }

  public String serialize() {
    return new String(contents, StandardCharsets.UTF_8);
  }

  public byte[] getContents() {
    return contents.clone();
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) return false;
    ProfileKeyVersion that = (ProfileKeyVersion) o;
    return Arrays.equals(contents, that.contents);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(contents);
  }

  @Override
  public String toString() {
    return "ProfileKeyVersion{" + "contents=" + Arrays.toString(contents) + '}';
  }
}

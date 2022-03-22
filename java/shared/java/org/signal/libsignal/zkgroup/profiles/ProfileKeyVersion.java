//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import java.io.UnsupportedEncodingException;

public final class ProfileKeyVersion {

  private byte[] contents;

  public ProfileKeyVersion(byte[] contents) throws InvalidInputException {
    if (contents.length != 64) {
      throw new InvalidInputException("bad length");
    }
    this.contents = contents.clone();
  }

  public ProfileKeyVersion(String contents) throws InvalidInputException, UnsupportedEncodingException {
    this(contents.getBytes("UTF-8"));
  }

  public String serialize() {
    try {
      return new String(contents, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError();
    }
  }

}

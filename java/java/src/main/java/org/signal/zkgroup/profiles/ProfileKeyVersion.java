//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import java.io.UnsupportedEncodingException;

public final class ProfileKeyVersion extends ByteArray {

  public static final int SIZE = 64;

  public ProfileKeyVersion(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }

  public ProfileKeyVersion(String contents) throws InvalidInputException, UnsupportedEncodingException {
    super(contents.getBytes("UTF-8"), SIZE);
  }

  public String serialize() {
    try {
      return new String(contents, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError();
    }
  }

}

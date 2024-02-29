//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groups;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class UuidCiphertext extends ByteArray {
  public UuidCiphertext(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.UuidCiphertext_CheckValidContents(contents);
  }

  public static byte[] serializeAndConcatenate(List<UuidCiphertext> ciphertexts) {
    ByteArrayOutputStream concatenated = new ByteArrayOutputStream();
    for (UuidCiphertext member : ciphertexts) {
      try {
        concatenated.write(member.getInternalContentsForJNI());
      } catch (IOException e) {
        // ByteArrayOutputStream should never fail.
        throw new AssertionError(e);
      }
    }
    return concatenated.toByteArray();
  }
}

//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.auth;

import java.nio.ByteBuffer;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.groups.UuidCiphertext;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class AuthCredentialPresentation extends ByteArray {

  public static final int SIZE = 493;

  public AuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    Native.AuthCredentialPresentation_CheckValidContents(contents);
  }

  public UuidCiphertext getUuidCiphertext() {
    byte[] newContents = Native.AuthCredentialPresentation_GetUuidCiphertext(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public int getRedemptionTime() {
    return Native.AuthCredentialPresentation_GetRedemptionTime(contents);
  }

  public byte[] serialize() {
    return contents.clone();
  }

}

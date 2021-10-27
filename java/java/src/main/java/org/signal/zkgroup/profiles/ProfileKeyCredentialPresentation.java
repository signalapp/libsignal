//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.groups.ProfileKeyCiphertext;
import org.signal.zkgroup.groups.UuidCiphertext;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class ProfileKeyCredentialPresentation extends ByteArray {

  public static final int SIZE = 713;

  public ProfileKeyCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    Native.ProfileKeyCredentialPresentation_CheckValidContents(contents);
  }

  public UuidCiphertext getUuidCiphertext() {
    byte[] newContents = Native.ProfileKeyCredentialPresentation_GetUuidCiphertext(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }

  }

  public ProfileKeyCiphertext getProfileKeyCiphertext() {
    byte[] newContents = Native.ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(contents);

    try {
      return new ProfileKeyCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }

  }

  public byte[] serialize() {
    return contents.clone();
  }

}

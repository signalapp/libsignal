//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.ProfileKeyCiphertext;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class PniCredentialPresentation extends ByteArray {

  public enum Version {V1, V2, UNKNOWN};

  public PniCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.PniCredentialPresentation_CheckValidContents(contents);
  }

  public UuidCiphertext getAciCiphertext() {
    byte[] newContents = Native.PniCredentialPresentation_GetAciCiphertext(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public UuidCiphertext getPniCiphertext() {
    byte[] newContents = Native.PniCredentialPresentation_GetPniCiphertext(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKeyCiphertext getProfileKeyCiphertext() {
    byte[] newContents = Native.PniCredentialPresentation_GetProfileKeyCiphertext(contents);

    try {
      return new ProfileKeyCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public Version getVersion() {
      if (this.contents[0] == 0) {
        return Version.V1;
      } else if (this.contents[0] == 1) {
        return Version.V2;
      } else {
        return Version.UNKNOWN;
      }
  }

}

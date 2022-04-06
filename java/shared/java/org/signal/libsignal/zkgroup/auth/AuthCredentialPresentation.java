//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import java.nio.ByteBuffer;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class AuthCredentialPresentation extends ByteArray {

  public enum Version {V1, V2, UNKNOWN};

  public AuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
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

//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import java.time.Instant;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class AuthCredentialPresentation extends ByteArray {

  public enum Version {V1, V2, V3, UNKNOWN};

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

  /**
   * Returns the PNI ciphertext for this credential. May be {@code null}.
   */
  public UuidCiphertext getPniCiphertext() {
    byte[] newContents = Native.AuthCredentialPresentation_GetPniCiphertext(contents);
    if (newContents == null) {
      return null;
    }

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public Instant getRedemptionTime() {
    return Instant.ofEpochSecond(Native.AuthCredentialPresentation_GetRedemptionTime(contents));
  }

  public Version getVersion() {
    switch (this.contents[0]) {
      case 0: return Version.V1;
      case 1: return Version.V2;
      case 2: return Version.V3;
      default: return Version.UNKNOWN;
    }
  }

}

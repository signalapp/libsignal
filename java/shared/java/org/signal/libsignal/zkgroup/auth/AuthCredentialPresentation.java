//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class AuthCredentialPresentation extends ByteArray {

  public enum Version {
    V1,
    V2,
    V3,
    V4,
    UNKNOWN
  };

  public AuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.AuthCredentialPresentation_CheckValidContents(contents));
  }

  public UuidCiphertext getUuidCiphertext() {
    byte[] newContents = Native.AuthCredentialPresentation_GetUuidCiphertext(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  /** Returns the PNI ciphertext for this credential. Will never be {@code null}. */
  public UuidCiphertext getPniCiphertext() {
    byte[] newContents = Native.AuthCredentialPresentation_GetPniCiphertext(contents);

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
    byte version = this.contents[0];
    final Version[] values = Version.values();
    if (version < values.length) {
      return values[version];
    }
    return Version.UNKNOWN;
  }
}

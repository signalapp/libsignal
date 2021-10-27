//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import java.util.UUID;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.VerificationFailedException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class ProfileKey extends ByteArray {

  public ProfileKey(byte[] contents) throws InvalidInputException {
    super(contents);
    try {
      Native.ProfileKey_CheckValidContents(contents);
    } catch (IllegalArgumentException e) {
      throw new InvalidInputException(e.getMessage());
    }
  }

  public ProfileKeyCommitment getCommitment(UUID uuid) {
    byte[] newContents = Native.ProfileKey_GetCommitment(contents, uuid);

    try {
      return new ProfileKeyCommitment(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKeyVersion getProfileKeyVersion(UUID uuid) {
    byte[] newContents = Native.ProfileKey_GetProfileKeyVersion(contents, uuid);

    try {
      return new ProfileKeyVersion(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}

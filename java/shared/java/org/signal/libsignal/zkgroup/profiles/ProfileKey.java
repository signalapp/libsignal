//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import java.util.UUID;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class ProfileKey extends ByteArray {

  public ProfileKey(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.ProfileKey_CheckValidContents(contents);
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

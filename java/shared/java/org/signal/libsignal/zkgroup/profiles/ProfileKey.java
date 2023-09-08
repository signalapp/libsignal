//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class ProfileKey extends ByteArray {

  public ProfileKey(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.ProfileKey_CheckValidContents(contents);
  }

  public ProfileKeyCommitment getCommitment(Aci userId) {
    byte[] newContents = Native.ProfileKey_GetCommitment(contents, userId.toServiceIdFixedWidthBinary());

    try {
      return new ProfileKeyCommitment(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKeyVersion getProfileKeyVersion(Aci userId) {
    byte[] newContents = Native.ProfileKey_GetProfileKeyVersion(contents, userId.toServiceIdFixedWidthBinary());

    try {
      return new ProfileKeyVersion(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] deriveAccessKey() {
    return Native.ProfileKey_DeriveAccessKey(contents);
  }

}

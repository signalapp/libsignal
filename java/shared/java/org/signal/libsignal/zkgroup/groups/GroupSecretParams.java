//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groups;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class GroupSecretParams extends ByteArray {

  public static GroupSecretParams generate() {
    return generate(new SecureRandom());
  }

  public static GroupSecretParams generate(SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.GroupSecretParams_GenerateDeterministic(random);

    try {
      return new GroupSecretParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public static GroupSecretParams deriveFromMasterKey(GroupMasterKey groupMasterKey) {
    byte[] newContents =
        Native.GroupSecretParams_DeriveFromMasterKey(groupMasterKey.getInternalContentsForJNI());

    try {
      return new GroupSecretParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public GroupSecretParams(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class, () -> Native.GroupSecretParams_CheckValidContents(contents));
  }

  public GroupMasterKey getMasterKey() {
    byte[] newContents = Native.GroupSecretParams_GetMasterKey(contents);

    try {
      return new GroupMasterKey(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public GroupPublicParams getPublicParams() {
    byte[] newContents = Native.GroupSecretParams_GetPublicParams(contents);

    try {
      return new GroupPublicParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

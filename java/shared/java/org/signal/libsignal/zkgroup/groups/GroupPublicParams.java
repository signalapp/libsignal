//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groups;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class GroupPublicParams extends ByteArray {

  public GroupPublicParams(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class, () -> Native.GroupPublicParams_CheckValidContents(contents));
  }

  public GroupIdentifier getGroupIdentifier() {
    byte[] newContents = Native.GroupPublicParams_GetGroupIdentifier(contents);

    try {
      return new GroupIdentifier(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

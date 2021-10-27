//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.groups;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class GroupPublicParams extends ByteArray {

  public static final int SIZE = 97;

  public GroupPublicParams(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    
    Native.GroupPublicParams_CheckValidContents(contents);
  }

  public GroupIdentifier getGroupIdentifier() {
    byte[] newContents = Native.GroupPublicParams_GetGroupIdentifier(contents);

    try {
      return new GroupIdentifier(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }

  }

  public byte[] serialize() {
    return contents.clone();
  }

}

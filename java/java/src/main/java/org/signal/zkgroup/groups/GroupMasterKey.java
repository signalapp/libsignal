//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.groups;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;

public final class GroupMasterKey extends ByteArray {

  public static final int SIZE = 32;

  public GroupMasterKey(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }

}

//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.groups;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;

public final class GroupIdentifier extends ByteArray {

  public static final int SIZE = 32;

  public GroupIdentifier(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }

}

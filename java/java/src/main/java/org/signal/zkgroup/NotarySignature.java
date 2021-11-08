//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup;

import org.signal.zkgroup.internal.ByteArray;

public final class NotarySignature extends ByteArray {

  public static final int SIZE = 64;

  public NotarySignature(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }

}

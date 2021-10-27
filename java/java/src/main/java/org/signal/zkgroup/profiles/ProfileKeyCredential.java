//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class ProfileKeyCredential extends ByteArray {

  public static final int SIZE = 145;

  public ProfileKeyCredential(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    Native.ProfileKeyCredential_CheckValidContents(contents);
  }

  public byte[] serialize() {
    return contents.clone();
  }

}

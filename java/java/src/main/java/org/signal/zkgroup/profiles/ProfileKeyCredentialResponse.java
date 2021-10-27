//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class ProfileKeyCredentialResponse extends ByteArray {

  public static final int SIZE = 457;

  public ProfileKeyCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    Native.ProfileKeyCredentialResponse_CheckValidContents(contents);
  }

  public byte[] serialize() {
    return contents.clone();
  }

}

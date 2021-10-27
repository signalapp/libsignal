//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.auth;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class AuthCredentialResponse extends ByteArray {

  public static final int SIZE = 361;

  public AuthCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    Native.AuthCredentialResponse_CheckValidContents(contents);
  }

  public byte[] serialize() {
    return contents.clone();
  }

}

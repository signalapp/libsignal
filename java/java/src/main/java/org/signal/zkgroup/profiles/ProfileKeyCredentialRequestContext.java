//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class ProfileKeyCredentialRequestContext extends ByteArray {

  public static final int SIZE = 473;

  public ProfileKeyCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
    Native.ProfileKeyCredentialRequestContext_CheckValidContents(contents);
  }

  public ProfileKeyCredentialRequest getRequest() {
    byte[] newContents = Native.ProfileKeyCredentialRequestContext_GetRequest(contents);

    try {
      return new ProfileKeyCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }

  }

  public byte[] serialize() {
    return contents.clone();
  }

}

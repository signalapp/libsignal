//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class ProfileKeyCredentialRequestContext extends ByteArray {
  public ProfileKeyCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents);
    try {
      Native.ProfileKeyCredentialRequestContext_CheckValidContents(contents);
    } catch (IllegalArgumentException e) {
      throw new InvalidInputException(e.getMessage());
    }
  }

  public ProfileKeyCredentialRequest getRequest() {
    byte[] newContents = Native.ProfileKeyCredentialRequestContext_GetRequest(contents);

    try {
      return new ProfileKeyCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

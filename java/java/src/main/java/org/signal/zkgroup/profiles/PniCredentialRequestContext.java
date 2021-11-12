//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

public final class PniCredentialRequestContext extends ByteArray {
  public PniCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents);
    try {
      Native.PniCredentialRequestContext_CheckValidContents(contents);
    } catch (IllegalArgumentException e) {
      throw new InvalidInputException(e.getMessage());
    }
  }

  public ProfileKeyCredentialRequest getRequest() {
    byte[] newContents = Native.PniCredentialRequestContext_GetRequest(contents);

    try {
      return new ProfileKeyCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

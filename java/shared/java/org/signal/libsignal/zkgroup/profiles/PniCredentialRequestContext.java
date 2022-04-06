//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class PniCredentialRequestContext extends ByteArray {
  public PniCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.PniCredentialRequestContext_CheckValidContents(contents);
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

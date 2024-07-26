//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class ProfileKeyCredentialRequestContext extends ByteArray {
  public ProfileKeyCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.ProfileKeyCredentialRequestContext_CheckValidContents(contents));
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

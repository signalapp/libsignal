//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class AuthCredentialWithPniResponse extends ByteArray {
  public AuthCredentialWithPniResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.AuthCredentialWithPniResponse_CheckValidContents(contents);
  }
}

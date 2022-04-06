//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class PniCredentialResponse extends ByteArray {
  public PniCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.PniCredentialResponse_CheckValidContents(contents);
  }
}

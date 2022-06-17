//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

import java.time.Instant;

public final class ExpiringProfileKeyCredential extends ByteArray {
  public ExpiringProfileKeyCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.ExpiringProfileKeyCredential_CheckValidContents(contents);
  }
  
  public Instant getExpirationTime() {
    return Instant.ofEpochSecond(Native.ExpiringProfileKeyCredential_GetExpirationTime(this.contents));
  }
}

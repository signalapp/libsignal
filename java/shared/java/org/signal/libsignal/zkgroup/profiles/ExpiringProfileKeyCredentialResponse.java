//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class ExpiringProfileKeyCredentialResponse extends ByteArray {
  public ExpiringProfileKeyCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.ExpiringProfileKeyCredentialResponse_CheckValidContents(contents));
  }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class CreateCallLinkCredentialResponse extends ByteArray {
  public CreateCallLinkCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CreateCallLinkCredentialResponse_CheckValidContents(contents));
  }
}

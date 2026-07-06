//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.avatars;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/** The issuing server's response to an {@link AvatarUploadCredentialRequest}. */
public final class AvatarUploadCredentialResponse extends ByteArray {

  public AvatarUploadCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.AvatarUploadCredentialResponse_CheckValidContents(contents));
  }
}

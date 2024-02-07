//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class ServerPublicParams extends ByteArray {
  public ServerPublicParams(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class, () -> Native.ServerPublicParams_CheckValidContents(contents));
  }

  public void verifySignature(byte[] message, NotarySignature notarySignature)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            Native.ServerPublicParams_VerifySignature(
                contents, message, notarySignature.getInternalContentsForJNI()));
  }
}

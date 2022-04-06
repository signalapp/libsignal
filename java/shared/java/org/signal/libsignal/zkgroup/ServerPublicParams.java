//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class ServerPublicParams extends ByteArray {
  public ServerPublicParams(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.ServerPublicParams_CheckValidContents(contents);
  }

  public void verifySignature(byte[] message, NotarySignature notarySignature) throws VerificationFailedException {
    Native.ServerPublicParams_VerifySignature(contents, message, notarySignature.getInternalContentsForJNI());
  }

}

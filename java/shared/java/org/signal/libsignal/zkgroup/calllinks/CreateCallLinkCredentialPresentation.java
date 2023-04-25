//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

import java.time.Instant;

public final class CreateCallLinkCredentialPresentation extends ByteArray {

  public CreateCallLinkCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.CreateCallLinkCredentialPresentation_CheckValidContents(contents);
  }

  public void verify(byte[] roomId, GenericServerSecretParams serverParams, CallLinkPublicParams callLinkParams) throws VerificationFailedException {
    verify(roomId, Instant.now(), serverParams, callLinkParams);
  }

  public void verify(byte[] roomId, Instant currentTime, GenericServerSecretParams serverParams, CallLinkPublicParams callLinkParams) throws VerificationFailedException {
    Native.CreateCallLinkCredentialPresentation_Verify(getInternalContentsForJNI(), roomId, currentTime.getEpochSecond(), serverParams.getInternalContentsForJNI(), callLinkParams.getInternalContentsForJNI());
  }

}

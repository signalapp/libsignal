//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

import java.time.Instant;

public final class CallLinkAuthCredentialPresentation extends ByteArray {

  public CallLinkAuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.CallLinkAuthCredentialPresentation_CheckValidContents(contents);
  }

  public void verify(GenericServerSecretParams serverParams, CallLinkPublicParams callLinkParams) throws VerificationFailedException {
    verify(Instant.now(), serverParams, callLinkParams);
  }

  public void verify(Instant currentTime, GenericServerSecretParams serverParams, CallLinkPublicParams callLinkParams) throws VerificationFailedException {
    Native.CallLinkAuthCredentialPresentation_Verify(getInternalContentsForJNI(), currentTime.getEpochSecond(), serverParams.getInternalContentsForJNI(), callLinkParams.getInternalContentsForJNI());
  }

  public UuidCiphertext getUserId() {
    byte[] newContents = Native.CallLinkAuthCredentialPresentation_GetUserId(contents);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}

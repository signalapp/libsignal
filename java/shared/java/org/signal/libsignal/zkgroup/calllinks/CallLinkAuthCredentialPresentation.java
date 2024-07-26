//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class CallLinkAuthCredentialPresentation extends ByteArray {

  public CallLinkAuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CallLinkAuthCredentialPresentation_CheckValidContents(contents));
  }

  public void verify(GenericServerSecretParams serverParams, CallLinkPublicParams callLinkParams)
      throws VerificationFailedException {
    verify(Instant.now(), serverParams, callLinkParams);
  }

  public void verify(
      Instant currentTime,
      GenericServerSecretParams serverParams,
      CallLinkPublicParams callLinkParams)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            Native.CallLinkAuthCredentialPresentation_Verify(
                getInternalContentsForJNI(),
                currentTime.getEpochSecond(),
                serverParams.getInternalContentsForJNI(),
                callLinkParams.getInternalContentsForJNI()));
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

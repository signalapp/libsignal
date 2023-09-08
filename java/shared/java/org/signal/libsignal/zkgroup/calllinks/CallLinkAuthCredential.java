//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

import java.security.SecureRandom;
import java.time.Instant;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public final class CallLinkAuthCredential extends ByteArray {

  public CallLinkAuthCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.CallLinkAuthCredential_CheckValidContents(contents);
  }

  public CallLinkAuthCredentialPresentation present(Aci userId, Instant redemptionTime, GenericServerPublicParams serverParams, CallLinkSecretParams callLinkParams) {
    return present(userId, redemptionTime, serverParams, callLinkParams, new SecureRandom());
  }

  public CallLinkAuthCredentialPresentation present(Aci userId, Instant redemptionTime, GenericServerPublicParams serverParams, CallLinkSecretParams callLinkParams, SecureRandom secureRandom) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.CallLinkAuthCredential_PresentDeterministic(getInternalContentsForJNI(), userId.toServiceIdFixedWidthBinary(), redemptionTime.getEpochSecond(), serverParams.getInternalContentsForJNI(), callLinkParams.getInternalContentsForJNI(), random);

    try {
      return new CallLinkAuthCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}

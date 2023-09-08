//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

import java.security.SecureRandom;
import java.time.Instant;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public final class CallLinkAuthCredentialResponse extends ByteArray {
  public CallLinkAuthCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.CallLinkAuthCredentialResponse_CheckValidContents(contents);
  }

  public static CallLinkAuthCredentialResponse issueCredential(Aci userId, Instant redemptionTime, GenericServerSecretParams params) {
    return issueCredential(userId, redemptionTime, params, new SecureRandom());
  }

  public static CallLinkAuthCredentialResponse issueCredential(Aci userId, Instant redemptionTime, GenericServerSecretParams params, SecureRandom secureRandom) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.CallLinkAuthCredentialResponse_IssueDeterministic(userId.toServiceIdFixedWidthBinary(), redemptionTime.getEpochSecond(), params.getInternalContentsForJNI(), random);

    try {
      return new CallLinkAuthCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public CallLinkAuthCredential receive(Aci userId, Instant redemptionTime, GenericServerPublicParams params) throws VerificationFailedException {
    byte[] newContents = Native.CallLinkAuthCredentialResponse_Receive(getInternalContentsForJNI(), userId.toServiceIdFixedWidthBinary(), redemptionTime.getEpochSecond(), params.getInternalContentsForJNI());

    try {
      return new CallLinkAuthCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

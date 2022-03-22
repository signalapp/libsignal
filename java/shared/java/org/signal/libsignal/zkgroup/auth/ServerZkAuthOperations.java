//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import java.security.SecureRandom;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.InvalidRedemptionTimeException;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.libsignal.internal.Native;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public class ServerZkAuthOperations {

  private final ServerSecretParams serverSecretParams;

  public ServerZkAuthOperations(ServerSecretParams serverSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  public AuthCredentialResponse issueAuthCredential(UUID uuid, int redemptionTime) {
    return issueAuthCredential(new SecureRandom(), uuid, redemptionTime);
  }

  public AuthCredentialResponse issueAuthCredential(SecureRandom secureRandom, UUID uuid, int redemptionTime) {
    byte[] random      = new byte[RANDOM_LENGTH];

    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_IssueAuthCredentialDeterministic(serverSecretParams.getInternalContentsForJNI(), random, uuid, redemptionTime);

    try {
      return new AuthCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public void verifyAuthCredentialPresentation(GroupPublicParams groupPublicParams, AuthCredentialPresentation authCredentialPresentation) throws VerificationFailedException, InvalidRedemptionTimeException {
       verifyAuthCredentialPresentation(groupPublicParams, authCredentialPresentation, System.currentTimeMillis());
     }

  public void verifyAuthCredentialPresentation(GroupPublicParams groupPublicParams, AuthCredentialPresentation authCredentialPresentation, long currentTimeMillis) throws VerificationFailedException, InvalidRedemptionTimeException {
    long acceptableStartTime = TimeUnit.MILLISECONDS.convert(authCredentialPresentation.getRedemptionTime()-1, TimeUnit.DAYS);
    long acceptableEndTime = TimeUnit.MILLISECONDS.convert(authCredentialPresentation.getRedemptionTime()+2, TimeUnit.DAYS);

    if (currentTimeMillis < acceptableStartTime || currentTimeMillis > acceptableEndTime) {
        throw new InvalidRedemptionTimeException();
    }

    Native.ServerSecretParams_VerifyAuthCredentialPresentation(serverSecretParams.getInternalContentsForJNI(), groupPublicParams.getInternalContentsForJNI(), authCredentialPresentation.getInternalContentsForJNI());
  }

}

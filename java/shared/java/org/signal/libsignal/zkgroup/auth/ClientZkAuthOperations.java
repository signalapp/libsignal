//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import java.security.SecureRandom;
import java.util.UUID;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.internal.Native;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public class ClientZkAuthOperations {

  private final ServerPublicParams serverPublicParams;

  public ClientZkAuthOperations(ServerPublicParams serverPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  public AuthCredential receiveAuthCredential(UUID uuid, int redemptionTime, AuthCredentialResponse authCredentialResponse) throws VerificationFailedException {
    byte[] newContents = Native.ServerPublicParams_ReceiveAuthCredential(serverPublicParams.getInternalContentsForJNI(), uuid, redemptionTime, authCredentialResponse.getInternalContentsForJNI());

    try {
      return new AuthCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public AuthCredentialPresentation createAuthCredentialPresentation(GroupSecretParams groupSecretParams, AuthCredential authCredential) {
    return createAuthCredentialPresentation(new SecureRandom(), groupSecretParams, authCredential);
  }

  public AuthCredentialPresentation createAuthCredentialPresentation(SecureRandom secureRandom, GroupSecretParams groupSecretParams, AuthCredential authCredential) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerPublicParams_CreateAuthCredentialPresentationDeterministic(serverPublicParams.getInternalContentsForJNI(), random, groupSecretParams.getInternalContentsForJNI(), authCredential.getInternalContentsForJNI());

    try {
      return new AuthCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}

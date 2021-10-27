//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import java.security.SecureRandom;
import java.util.UUID;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.ServerPublicParams;
import org.signal.zkgroup.VerificationFailedException;
import org.signal.zkgroup.groups.GroupSecretParams;
import org.signal.client.internal.Native;

import static org.signal.zkgroup.internal.Constants.RANDOM_LENGTH;

public class ClientZkProfileOperations {

  private final ServerPublicParams serverPublicParams;

  public ClientZkProfileOperations(ServerPublicParams serverPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  public ProfileKeyCredentialRequestContext createProfileKeyCredentialRequestContext(UUID uuid, ProfileKey profileKey) {
    return createProfileKeyCredentialRequestContext(new SecureRandom(), uuid, profileKey);
  }

  public ProfileKeyCredentialRequestContext createProfileKeyCredentialRequestContext(SecureRandom secureRandom, UUID uuid, ProfileKey profileKey) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(serverPublicParams.getInternalContentsForJNI(), random, uuid, profileKey.getInternalContentsForJNI());

    try {
      return new ProfileKeyCredentialRequestContext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKeyCredential receiveProfileKeyCredential(ProfileKeyCredentialRequestContext profileKeyCredentialRequestContext, ProfileKeyCredentialResponse profileKeyCredentialResponse) throws VerificationFailedException {
    if (profileKeyCredentialResponse == null) {
      throw new VerificationFailedException();
    }

    byte[] newContents = Native.ServerPublicParams_ReceiveProfileKeyCredential(serverPublicParams.getInternalContentsForJNI(), profileKeyCredentialRequestContext.getInternalContentsForJNI(), profileKeyCredentialResponse.getInternalContentsForJNI());

    try {
      return new ProfileKeyCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKeyCredentialPresentation createProfileKeyCredentialPresentation(GroupSecretParams groupSecretParams, ProfileKeyCredential profileKeyCredential) {
    return createProfileKeyCredentialPresentation(new SecureRandom(), groupSecretParams, profileKeyCredential);
  }

  public ProfileKeyCredentialPresentation createProfileKeyCredentialPresentation(SecureRandom secureRandom, GroupSecretParams groupSecretParams, ProfileKeyCredential profileKeyCredential) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerPublicParams_CreateProfileKeyCredentialPresentationDeterministic(serverPublicParams.getInternalContentsForJNI(), random, groupSecretParams.getInternalContentsForJNI(), profileKeyCredential.getInternalContentsForJNI());

    try {
      return new ProfileKeyCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}

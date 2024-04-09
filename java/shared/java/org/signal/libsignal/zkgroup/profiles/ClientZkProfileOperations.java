//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;

public class ClientZkProfileOperations {

  private final ServerPublicParams serverPublicParams;

  public ClientZkProfileOperations(ServerPublicParams serverPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  public ProfileKeyCredentialRequestContext createProfileKeyCredentialRequestContext(
      Aci userId, ProfileKey profileKey) {
    return createProfileKeyCredentialRequestContext(new SecureRandom(), userId, profileKey);
  }

  public ProfileKeyCredentialRequestContext createProfileKeyCredentialRequestContext(
      SecureRandom secureRandom, Aci userId, ProfileKey profileKey) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        serverPublicParams.guardedMap(
            (serverPublicParams) ->
                Native.ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(
                    serverPublicParams,
                    random,
                    userId.toServiceIdFixedWidthBinary(),
                    profileKey.getInternalContentsForJNI()));

    try {
      return new ProfileKeyCredentialRequestContext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ExpiringProfileKeyCredential receiveExpiringProfileKeyCredential(
      ProfileKeyCredentialRequestContext profileKeyCredentialRequestContext,
      ExpiringProfileKeyCredentialResponse profileKeyCredentialResponse)
      throws VerificationFailedException {
    return receiveExpiringProfileKeyCredential(
        profileKeyCredentialRequestContext, profileKeyCredentialResponse, Instant.now());
  }

  public ExpiringProfileKeyCredential receiveExpiringProfileKeyCredential(
      ProfileKeyCredentialRequestContext profileKeyCredentialRequestContext,
      ExpiringProfileKeyCredentialResponse profileKeyCredentialResponse,
      Instant now)
      throws VerificationFailedException {
    if (profileKeyCredentialResponse == null) {
      throw new VerificationFailedException();
    }

    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                serverPublicParams.guardedMapChecked(
                    (publicParams) ->
                        Native.ServerPublicParams_ReceiveExpiringProfileKeyCredential(
                            publicParams,
                            profileKeyCredentialRequestContext.getInternalContentsForJNI(),
                            profileKeyCredentialResponse.getInternalContentsForJNI(),
                            now.getEpochSecond())));

    try {
      return new ExpiringProfileKeyCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKeyCredentialPresentation createProfileKeyCredentialPresentation(
      GroupSecretParams groupSecretParams, ExpiringProfileKeyCredential profileKeyCredential) {
    return createProfileKeyCredentialPresentation(
        new SecureRandom(), groupSecretParams, profileKeyCredential);
  }

  public ProfileKeyCredentialPresentation createProfileKeyCredentialPresentation(
      SecureRandom secureRandom,
      GroupSecretParams groupSecretParams,
      ExpiringProfileKeyCredential profileKeyCredential) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        serverPublicParams.guardedMap(
            (publicParams) ->
                Native
                    .ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(
                        publicParams,
                        random,
                        groupSecretParams.getInternalContentsForJNI(),
                        profileKeyCredential.getInternalContentsForJNI()));

    try {
      return new ProfileKeyCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

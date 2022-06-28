//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.internal.Native;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

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

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential.
   */
  @Deprecated
  public PniCredentialRequestContext createPniCredentialRequestContext(UUID aci, UUID pni, ProfileKey profileKey) {
    return createPniCredentialRequestContext(new SecureRandom(), aci, pni, profileKey);
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential.
   */
  @Deprecated
  public PniCredentialRequestContext createPniCredentialRequestContext(SecureRandom secureRandom, UUID aci, UUID pni, ProfileKey profileKey) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerPublicParams_CreatePniCredentialRequestContextDeterministic(serverPublicParams.getInternalContentsForJNI(), random, aci, pni, profileKey.getInternalContentsForJNI());

    try {
      return new PniCredentialRequestContext(newContents);
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

  public ExpiringProfileKeyCredential receiveExpiringProfileKeyCredential(ProfileKeyCredentialRequestContext profileKeyCredentialRequestContext, ExpiringProfileKeyCredentialResponse profileKeyCredentialResponse) throws VerificationFailedException {
    return receiveExpiringProfileKeyCredential(profileKeyCredentialRequestContext, profileKeyCredentialResponse, Instant.now());
  }

  public ExpiringProfileKeyCredential receiveExpiringProfileKeyCredential(ProfileKeyCredentialRequestContext profileKeyCredentialRequestContext, ExpiringProfileKeyCredentialResponse profileKeyCredentialResponse, Instant now) throws VerificationFailedException {
    if (profileKeyCredentialResponse == null) {
      throw new VerificationFailedException();
    }

    byte[] newContents = Native.ServerPublicParams_ReceiveExpiringProfileKeyCredential(serverPublicParams.getInternalContentsForJNI(), profileKeyCredentialRequestContext.getInternalContentsForJNI(), profileKeyCredentialResponse.getInternalContentsForJNI(), now.getEpochSecond());

    try {
      return new ExpiringProfileKeyCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential.
   */
  @Deprecated
  public PniCredential receivePniCredential(PniCredentialRequestContext requestContext, PniCredentialResponse response) throws VerificationFailedException {
    if (response == null) {
      throw new VerificationFailedException();
    }

    byte[] newContents = Native.ServerPublicParams_ReceivePniCredential(serverPublicParams.getInternalContentsForJNI(), requestContext.getInternalContentsForJNI(), response.getInternalContentsForJNI());

    try {
      return new PniCredential(newContents);
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

  public ProfileKeyCredentialPresentation createProfileKeyCredentialPresentation(GroupSecretParams groupSecretParams, ExpiringProfileKeyCredential profileKeyCredential) {
    return createProfileKeyCredentialPresentation(new SecureRandom(), groupSecretParams, profileKeyCredential);
  }

  public ProfileKeyCredentialPresentation createProfileKeyCredentialPresentation(SecureRandom secureRandom, GroupSecretParams groupSecretParams, ExpiringProfileKeyCredential profileKeyCredential) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(serverPublicParams.getInternalContentsForJNI(), random, groupSecretParams.getInternalContentsForJNI(), profileKeyCredential.getInternalContentsForJNI());

    try {
      return new ProfileKeyCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential.
   */
  @Deprecated
  public PniCredentialPresentation createPniCredentialPresentation(GroupSecretParams groupSecretParams, PniCredential credential) {
    return createPniCredentialPresentation(new SecureRandom(), groupSecretParams, credential);
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential.
   */
  @Deprecated
  public PniCredentialPresentation createPniCredentialPresentation(SecureRandom secureRandom, GroupSecretParams groupSecretParams, PniCredential credential) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerPublicParams_CreatePniCredentialPresentationDeterministic(serverPublicParams.getInternalContentsForJNI(), random, groupSecretParams.getInternalContentsForJNI(), credential.getInternalContentsForJNI());

    try {
      return new PniCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}

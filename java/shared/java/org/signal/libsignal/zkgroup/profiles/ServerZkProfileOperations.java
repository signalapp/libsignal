//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.libsignal.internal.Native;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public class ServerZkProfileOperations {

  private final ServerSecretParams serverSecretParams;

  public ServerZkProfileOperations(ServerSecretParams serverSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  public ProfileKeyCredentialResponse issueProfileKeyCredential(ProfileKeyCredentialRequest profileKeyCredentialRequest, UUID uuid, ProfileKeyCommitment profileKeyCommitment) throws VerificationFailedException {
    return issueProfileKeyCredential(new SecureRandom(), profileKeyCredentialRequest, uuid, profileKeyCommitment);
  }

  public ProfileKeyCredentialResponse issueProfileKeyCredential(SecureRandom secureRandom, ProfileKeyCredentialRequest profileKeyCredentialRequest, UUID uuid, ProfileKeyCommitment profileKeyCommitment) throws VerificationFailedException {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_IssueProfileKeyCredentialDeterministic(serverSecretParams.getInternalContentsForJNI(), random, profileKeyCredentialRequest.getInternalContentsForJNI(), uuid, profileKeyCommitment.getInternalContentsForJNI());

    try {
      return new ProfileKeyCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ExpiringProfileKeyCredentialResponse issueExpiringProfileKeyCredential(ProfileKeyCredentialRequest profileKeyCredentialRequest, UUID uuid, ProfileKeyCommitment profileKeyCommitment, Instant expiration) throws VerificationFailedException {
    return issueExpiringProfileKeyCredential(new SecureRandom(), profileKeyCredentialRequest, uuid, profileKeyCommitment, expiration);
  }

  /**
   * Issues an ExpiringProfileKeyCredential.
   *
   * @param expiration Must be a round number of days. Use {@link java.time.Instant#truncatedTo} to
   * ensure this.
   */
  public ExpiringProfileKeyCredentialResponse issueExpiringProfileKeyCredential(SecureRandom secureRandom, ProfileKeyCredentialRequest profileKeyCredentialRequest, UUID uuid, ProfileKeyCommitment profileKeyCommitment, Instant expiration) throws VerificationFailedException {
    assert expiration.equals(expiration.truncatedTo(ChronoUnit.DAYS));

    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(serverSecretParams.getInternalContentsForJNI(), random, profileKeyCredentialRequest.getInternalContentsForJNI(), uuid, profileKeyCommitment.getInternalContentsForJNI(), expiration.getEpochSecond());

    try {
      return new ExpiringProfileKeyCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential.
   */
  @Deprecated
  public PniCredentialResponse issuePniCredential(ProfileKeyCredentialRequest request, UUID aci, UUID pni, ProfileKeyCommitment profileKeyCommitment) throws VerificationFailedException {
    return issuePniCredential(new SecureRandom(), request, aci, pni, profileKeyCommitment);
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential.
   */
  @Deprecated
  public PniCredentialResponse issuePniCredential(SecureRandom secureRandom, ProfileKeyCredentialRequest request, UUID aci, UUID pni, ProfileKeyCommitment profileKeyCommitment) throws VerificationFailedException {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_IssuePniCredentialDeterministic(serverSecretParams.getInternalContentsForJNI(), random, request.getInternalContentsForJNI(), aci, pni, profileKeyCommitment.getInternalContentsForJNI());

    try {
      return new PniCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public void verifyProfileKeyCredentialPresentation(GroupPublicParams groupPublicParams, ProfileKeyCredentialPresentation profileKeyCredentialPresentation) throws VerificationFailedException {
    verifyProfileKeyCredentialPresentation(groupPublicParams, profileKeyCredentialPresentation, Instant.now());
  }

  public void verifyProfileKeyCredentialPresentation(GroupPublicParams groupPublicParams, ProfileKeyCredentialPresentation profileKeyCredentialPresentation, Instant now) throws VerificationFailedException {
    Native.ServerSecretParams_VerifyProfileKeyCredentialPresentation(serverSecretParams.getInternalContentsForJNI(), groupPublicParams.getInternalContentsForJNI(), profileKeyCredentialPresentation.getInternalContentsForJNI(), now.getEpochSecond());
  }

  /**
   * @deprecated Superseded by AuthCredentialWithPni + ProfileKeyCredential.
   */
  @Deprecated
  public void verifyPniCredentialPresentation(GroupPublicParams groupPublicParams, PniCredentialPresentation presentation) throws VerificationFailedException {
    Native.ServerSecretParams_VerifyPniCredentialPresentation(serverSecretParams.getInternalContentsForJNI(), groupPublicParams.getInternalContentsForJNI(), presentation.getInternalContentsForJNI());
  }
}

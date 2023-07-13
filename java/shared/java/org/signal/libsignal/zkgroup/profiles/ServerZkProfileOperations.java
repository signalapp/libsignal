//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.signal.libsignal.protocol.ServiceId.Aci;
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

  public ExpiringProfileKeyCredentialResponse issueExpiringProfileKeyCredential(ProfileKeyCredentialRequest profileKeyCredentialRequest, Aci userId, ProfileKeyCommitment profileKeyCommitment, Instant expiration) throws VerificationFailedException {
    return issueExpiringProfileKeyCredential(new SecureRandom(), profileKeyCredentialRequest, userId, profileKeyCommitment, expiration);
  }

  /**
   * Issues an ExpiringProfileKeyCredential.
   *
   * @param expiration Must be a round number of days. Use {@link java.time.Instant#truncatedTo} to
   * ensure this.
   */
  public ExpiringProfileKeyCredentialResponse issueExpiringProfileKeyCredential(SecureRandom secureRandom, ProfileKeyCredentialRequest profileKeyCredentialRequest, Aci userId, ProfileKeyCommitment profileKeyCommitment, Instant expiration) throws VerificationFailedException {
    assert expiration.equals(expiration.truncatedTo(ChronoUnit.DAYS));

    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(serverSecretParams.getInternalContentsForJNI(), random, profileKeyCredentialRequest.getInternalContentsForJNI(), userId.toServiceIdFixedWidthBinary(), profileKeyCommitment.getInternalContentsForJNI(), expiration.getEpochSecond());

    try {
      return new ExpiringProfileKeyCredentialResponse(newContents);
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

}

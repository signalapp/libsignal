//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.profiles;

import java.security.SecureRandom;
import java.util.UUID;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.ServerSecretParams;
import org.signal.zkgroup.VerificationFailedException;
import org.signal.zkgroup.groups.GroupPublicParams;
import org.signal.client.internal.Native;

import static org.signal.zkgroup.internal.Constants.RANDOM_LENGTH;

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

  public PniCredentialResponse issuePniCredential(ProfileKeyCredentialRequest request, UUID aci, UUID pni, ProfileKeyCommitment profileKeyCommitment) throws VerificationFailedException {
    return issuePniCredential(new SecureRandom(), request, aci, pni, profileKeyCommitment);
  }

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
    Native.ServerSecretParams_VerifyProfileKeyCredentialPresentation(serverSecretParams.getInternalContentsForJNI(), groupPublicParams.getInternalContentsForJNI(), profileKeyCredentialPresentation.getInternalContentsForJNI());
  }

  public void verifyPniCredentialPresentation(GroupPublicParams groupPublicParams, PniCredentialPresentation presentation) throws VerificationFailedException {
    Native.ServerSecretParams_VerifyPniCredentialPresentation(serverSecretParams.getInternalContentsForJNI(), groupPublicParams.getInternalContentsForJNI(), presentation.getInternalContentsForJNI());
  }
}

//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import java.security.SecureRandom;
import java.time.Instant;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ServiceId.Pni;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.libsignal.internal.Native;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public class ServerZkAuthOperations {

  private final ServerSecretParams serverSecretParams;

  public ServerZkAuthOperations(ServerSecretParams serverSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  public AuthCredentialResponse issueAuthCredential(Aci aci, int redemptionTime) {
    return issueAuthCredential(new SecureRandom(), aci, redemptionTime);
  }

  public AuthCredentialResponse issueAuthCredential(SecureRandom secureRandom, Aci aci, int redemptionTime) {
    byte[] random      = new byte[RANDOM_LENGTH];

    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_IssueAuthCredentialDeterministic(serverSecretParams.getInternalContentsForJNI(), random, aci.toServiceIdFixedWidthBinary(), redemptionTime);

    try {
      return new AuthCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniAsServiceId(Aci aci, Pni pni, Instant redemptionTime) {
    return issueAuthCredentialWithPniAsServiceId(new SecureRandom(), aci, pni, redemptionTime);
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniAsServiceId(SecureRandom secureRandom, Aci aci, Pni pni, Instant redemptionTime) {
    byte[] random      = new byte[RANDOM_LENGTH];

    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_IssueAuthCredentialWithPniAsServiceIdDeterministic(serverSecretParams.getInternalContentsForJNI(), random, aci.toServiceIdFixedWidthBinary(), pni.toServiceIdFixedWidthBinary(), redemptionTime.getEpochSecond());

    try {
      return new AuthCredentialWithPniResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniAsAci(Aci aci, Pni pni, Instant redemptionTime) {
    return issueAuthCredentialWithPniAsAci(new SecureRandom(), aci, pni, redemptionTime);
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniAsAci(SecureRandom secureRandom, Aci aci, Pni pni, Instant redemptionTime) {
    byte[] random      = new byte[RANDOM_LENGTH];

    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_IssueAuthCredentialWithPniAsAciDeterministic(serverSecretParams.getInternalContentsForJNI(), random, aci.toServiceIdFixedWidthBinary(), pni.toServiceIdFixedWidthBinary(), redemptionTime.getEpochSecond());

    try {
      return new AuthCredentialWithPniResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public void verifyAuthCredentialPresentation(GroupPublicParams groupPublicParams, AuthCredentialPresentation authCredentialPresentation) throws VerificationFailedException {
       verifyAuthCredentialPresentation(groupPublicParams, authCredentialPresentation, Instant.now());
     }

  public void verifyAuthCredentialPresentation(GroupPublicParams groupPublicParams, AuthCredentialPresentation authCredentialPresentation, Instant currentTime) throws VerificationFailedException {
    Native.ServerSecretParams_VerifyAuthCredentialPresentation(serverSecretParams.getInternalContentsForJNI(), groupPublicParams.getInternalContentsForJNI(), authCredentialPresentation.getInternalContentsForJNI(), currentTime.getEpochSecond());
  }

}

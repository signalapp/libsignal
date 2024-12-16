//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ServiceId.Pni;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;

public class ServerZkAuthOperations {

  private final ServerSecretParams serverSecretParams;

  public ServerZkAuthOperations(ServerSecretParams serverSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniZkc(
      Aci aci, Pni pni, Instant redemptionTime) {
    return issueAuthCredentialWithPniZkc(new SecureRandom(), aci, pni, redemptionTime);
  }

  public AuthCredentialWithPniResponse issueAuthCredentialWithPniZkc(
      SecureRandom secureRandom, Aci aci, Pni pni, Instant redemptionTime) {
    byte[] random = new byte[RANDOM_LENGTH];

    secureRandom.nextBytes(random);

    byte[] newContents =
        serverSecretParams.guardedMap(
            (serverSecretParams) ->
                Native.ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic(
                    serverSecretParams,
                    random,
                    aci.toServiceIdFixedWidthBinary(),
                    pni.toServiceIdFixedWidthBinary(),
                    redemptionTime.getEpochSecond()));

    try {
      return new AuthCredentialWithPniResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public void verifyAuthCredentialPresentation(
      GroupPublicParams groupPublicParams, AuthCredentialPresentation authCredentialPresentation)
      throws VerificationFailedException {
    verifyAuthCredentialPresentation(groupPublicParams, authCredentialPresentation, Instant.now());
  }

  public void verifyAuthCredentialPresentation(
      GroupPublicParams groupPublicParams,
      AuthCredentialPresentation authCredentialPresentation,
      Instant currentTime)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            serverSecretParams.guardedRunChecked(
                (secretParams) ->
                    Native.ServerSecretParams_VerifyAuthCredentialPresentation(
                        secretParams,
                        groupPublicParams.getInternalContentsForJNI(),
                        authCredentialPresentation.getInternalContentsForJNI(),
                        currentTime.getEpochSecond())));
  }
}

//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.auth;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ServiceId.Pni;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;

public class ClientZkAuthOperations {

  private final ServerPublicParams serverPublicParams;

  public ClientZkAuthOperations(ServerPublicParams serverPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  /**
   * Produces the AuthCredentialWithPni from a server-generated AuthCredentialWithPniResponse.
   *
   * @param redemptionTime This is provided by the server as an integer, and should be passed
   *     through directly.
   */
  public AuthCredentialWithPni receiveAuthCredentialWithPniAsServiceId(
      Aci aci, Pni pni, long redemptionTime, AuthCredentialWithPniResponse authCredentialResponse)
      throws VerificationFailedException {
    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                serverPublicParams.guardedMapChecked(
                    (publicParams) ->
                        Native.ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(
                            publicParams,
                            aci.toServiceIdFixedWidthBinary(),
                            pni.toServiceIdFixedWidthBinary(),
                            redemptionTime,
                            authCredentialResponse.getInternalContentsForJNI())));

    try {
      return new AuthCredentialWithPni(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public AuthCredentialPresentation createAuthCredentialPresentation(
      GroupSecretParams groupSecretParams, AuthCredentialWithPni authCredential) {
    return createAuthCredentialPresentation(new SecureRandom(), groupSecretParams, authCredential);
  }

  public AuthCredentialPresentation createAuthCredentialPresentation(
      SecureRandom secureRandom,
      GroupSecretParams groupSecretParams,
      AuthCredentialWithPni authCredential) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        serverPublicParams.guardedMap(
            (publicParams) ->
                Native.ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(
                    publicParams,
                    random,
                    groupSecretParams.getInternalContentsForJNI(),
                    authCredential.getInternalContentsForJNI()));

    try {
      return new AuthCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

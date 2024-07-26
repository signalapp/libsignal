//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.receipts;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;

public class ServerZkReceiptOperations {

  private final ServerSecretParams serverSecretParams;

  public ServerZkReceiptOperations(ServerSecretParams serverSecretParams) {
    this.serverSecretParams = serverSecretParams;
  }

  public ReceiptCredentialResponse issueReceiptCredential(
      ReceiptCredentialRequest receiptCredentialRequest,
      long receiptExpirationTime,
      long receiptLevel)
      throws VerificationFailedException {
    return issueReceiptCredential(
        new SecureRandom(), receiptCredentialRequest, receiptExpirationTime, receiptLevel);
  }

  public ReceiptCredentialResponse issueReceiptCredential(
      SecureRandom secureRandom,
      ReceiptCredentialRequest receiptCredentialRequest,
      long receiptExpirationTime,
      long receiptLevel)
      throws VerificationFailedException {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        serverSecretParams.guardedMap(
            (serverSecretParams) ->
                Native.ServerSecretParams_IssueReceiptCredentialDeterministic(
                    serverSecretParams,
                    random,
                    receiptCredentialRequest.getInternalContentsForJNI(),
                    receiptExpirationTime,
                    receiptLevel));

    try {
      return new ReceiptCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public void verifyReceiptCredentialPresentation(
      ReceiptCredentialPresentation receiptCredentialPresentation)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            serverSecretParams.guardedRunChecked(
                (secretParams) ->
                    Native.ServerSecretParams_VerifyReceiptCredentialPresentation(
                        secretParams, receiptCredentialPresentation.getInternalContentsForJNI())));
  }
}

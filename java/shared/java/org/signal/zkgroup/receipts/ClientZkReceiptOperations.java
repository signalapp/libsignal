//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup.receipts;

import java.security.SecureRandom;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.ServerPublicParams;
import org.signal.zkgroup.VerificationFailedException;
import org.signal.client.internal.Native;

import static org.signal.zkgroup.internal.Constants.RANDOM_LENGTH;

public class ClientZkReceiptOperations {

  private final ServerPublicParams serverPublicParams;

  public ClientZkReceiptOperations(ServerPublicParams serverPublicParams) {
    this.serverPublicParams = serverPublicParams;
  }

  public ReceiptCredentialRequestContext createReceiptCredentialRequestContext(ReceiptSerial receiptSerial) throws VerificationFailedException {
    return createReceiptCredentialRequestContext(new SecureRandom(), receiptSerial);
  }

  public ReceiptCredentialRequestContext createReceiptCredentialRequestContext(SecureRandom secureRandom, ReceiptSerial receiptSerial) throws VerificationFailedException {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(serverPublicParams.getInternalContentsForJNI(), random, receiptSerial.getInternalContentsForJNI());

    try {
      return new ReceiptCredentialRequestContext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ReceiptCredential receiveReceiptCredential(ReceiptCredentialRequestContext receiptCredentialRequestContext, ReceiptCredentialResponse receiptCredentialResponse) throws VerificationFailedException {
    byte[] newContents = Native.ServerPublicParams_ReceiveReceiptCredential(serverPublicParams.getInternalContentsForJNI(), receiptCredentialRequestContext.getInternalContentsForJNI(), receiptCredentialResponse.getInternalContentsForJNI());

    try {
      return new ReceiptCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ReceiptCredentialPresentation createReceiptCredentialPresentation(ReceiptCredential receiptCredential) throws VerificationFailedException {
    return createReceiptCredentialPresentation(new SecureRandom(), receiptCredential);
  }

  public ReceiptCredentialPresentation createReceiptCredentialPresentation(SecureRandom secureRandom, ReceiptCredential receiptCredential) throws VerificationFailedException {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(serverPublicParams.getInternalContentsForJNI(), random, receiptCredential.getInternalContentsForJNI());

    try {
      return new ReceiptCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}

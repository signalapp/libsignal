//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

import java.security.SecureRandom;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public final class CreateCallLinkCredentialRequestContext extends ByteArray {

  public CreateCallLinkCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.CreateCallLinkCredentialRequestContext_CheckValidContents(contents);
  }

  public static CreateCallLinkCredentialRequestContext forRoom(byte[] roomId) {
    return forRoom(roomId, new SecureRandom());
  }

  public static CreateCallLinkCredentialRequestContext forRoom(byte[] roomId, SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.CreateCallLinkCredentialRequestContext_NewDeterministic(roomId, random);

    try {
      return new CreateCallLinkCredentialRequestContext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    } 
  }

  public CreateCallLinkCredentialRequest getRequest() {
    byte[] newContents = Native.CreateCallLinkCredentialRequestContext_GetRequest(contents);

    try {
      return new CreateCallLinkCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public CreateCallLinkCredential receiveResponse(CreateCallLinkCredentialResponse response, Aci userId, GenericServerPublicParams params) throws VerificationFailedException {
    byte[] newContents = Native.CreateCallLinkCredentialRequestContext_ReceiveResponse(getInternalContentsForJNI(), response.getInternalContentsForJNI(), userId.toServiceIdFixedWidthBinary(), params.getInternalContentsForJNI());

    try {
      return new CreateCallLinkCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}

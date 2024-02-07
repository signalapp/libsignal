//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class CreateCallLinkCredential extends ByteArray {

  public CreateCallLinkCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.CreateCallLinkCredential_CheckValidContents(contents));
  }

  public CreateCallLinkCredentialPresentation present(
      byte[] roomId,
      Aci userId,
      GenericServerPublicParams serverParams,
      CallLinkSecretParams callLinkParams) {
    return present(roomId, userId, serverParams, callLinkParams, new SecureRandom());
  }

  public CreateCallLinkCredentialPresentation present(
      byte[] roomId,
      Aci userId,
      GenericServerPublicParams serverParams,
      CallLinkSecretParams callLinkParams,
      SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        filterExceptions(
            () ->
                Native.CreateCallLinkCredential_PresentDeterministic(
                    getInternalContentsForJNI(),
                    roomId,
                    userId.toServiceIdFixedWidthBinary(),
                    serverParams.getInternalContentsForJNI(),
                    callLinkParams.getInternalContentsForJNI(),
                    random));

    try {
      return new CreateCallLinkCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

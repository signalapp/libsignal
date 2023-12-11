//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groupsend;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class GroupSendCredential extends ByteArray {

  public GroupSendCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.GroupSendCredential_CheckValidContents(contents);
  }

  public GroupSendCredentialPresentation present(ServerPublicParams serverParams) {
    return present(serverParams, new SecureRandom());
  }

  public GroupSendCredentialPresentation present(
      ServerPublicParams serverParams, SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.GroupSendCredential_PresentDeterministic(
            getInternalContentsForJNI(), serverParams.getInternalContentsForJNI(), random);

    try {
      return new GroupSendCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

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

/**
 * A credential indicating membership in a group, based on the set of <em>other</em> users in the
 * group with you.
 *
 * <p>Follows the usual zkgroup pattern of "issue response -> receive response -> present credential
 * -> verify presentation".
 *
 * @see GroupSendCredentialResponse
 * @see GroupSendCredentialPresentation
 */
public final class GroupSendCredential extends ByteArray {

  public GroupSendCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.GroupSendCredential_CheckValidContents(contents);
  }

  /** Generates a new presentation, so that multiple uses of this credential are harder to link. */
  public GroupSendCredentialPresentation present(ServerPublicParams serverParams) {
    return present(serverParams, new SecureRandom());
  }

  /**
   * Generates a new presentation with a dedicated source of randomness.
   *
   * <p>Should only be used for testing purposes.
   *
   * @see #present(ServerPublicParams)
   */
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

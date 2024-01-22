//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groupsend;

import java.time.Instant;
import java.util.List;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/**
 * A credential presentation indicating membership in a group, based on the set of <em>other</em>
 * users in the group with you.
 *
 * <p>Follows the usual zkgroup pattern of "issue response -> receive response -> present credential
 * -> verify presentation".
 *
 * @see GroupSendCredentialResponse
 * @see GroupSendCredential
 */
public final class GroupSendCredentialPresentation extends ByteArray {

  public GroupSendCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.GroupSendCredentialPresentation_CheckValidContents(contents);
  }

  /**
   * Verifies that the credential is valid for a group containing the holder and {@code
   * groupMembers}.
   *
   * @throws VerificationFailedException if the credential is not valid for any reason
   */
  public void verify(List<ServiceId> groupMembers, ServerSecretParams serverParams)
      throws VerificationFailedException {
    verify(groupMembers, Instant.now(), serverParams);
  }

  /**
   * Verifies that the credential would be valid for a group containing the holder and {@code
   * groupMembers} at a given time.
   *
   * <p>Should only be used for testing purposes.
   *
   * @throws VerificationFailedException if the credential is not valid for any reason
   * @see #verify(List, ServerSecretParams)
   */
  public void verify(
      List<ServiceId> groupMembers, Instant currentTime, ServerSecretParams serverParams)
      throws VerificationFailedException {
    Native.GroupSendCredentialPresentation_Verify(
        getInternalContentsForJNI(),
        ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
        currentTime.getEpochSecond(),
        serverParams.getInternalContentsForJNI());
  }
}

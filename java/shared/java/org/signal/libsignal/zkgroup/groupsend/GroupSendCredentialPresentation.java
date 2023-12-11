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

public final class GroupSendCredentialPresentation extends ByteArray {

  public GroupSendCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.GroupSendCredentialPresentation_CheckValidContents(contents);
  }

  public void verify(List<ServiceId> groupMembers, ServerSecretParams serverParams)
      throws VerificationFailedException {
    verify(groupMembers, Instant.now(), serverParams);
  }

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

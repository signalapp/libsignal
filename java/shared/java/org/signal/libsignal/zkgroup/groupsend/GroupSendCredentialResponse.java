//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groupsend;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class GroupSendCredentialResponse extends ByteArray {
  public GroupSendCredentialResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.GroupSendCredentialResponse_CheckValidContents(contents);
  }

  private static Instant defaultExpiration() {
    long expirationEpochSecond =
        Native.GroupSendCredentialResponse_DefaultExpirationBasedOnCurrentTime();
    return Instant.ofEpochSecond(expirationEpochSecond);
  }

  public static GroupSendCredentialResponse issueCredential(
      List<UuidCiphertext> groupMembers, UuidCiphertext requestingUser, ServerSecretParams params) {
    return issueCredential(
        groupMembers, requestingUser, defaultExpiration(), params, new SecureRandom());
  }

  public static GroupSendCredentialResponse issueCredential(
      List<UuidCiphertext> groupMembers,
      UuidCiphertext requestingUser,
      Instant expiration,
      ServerSecretParams params,
      SecureRandom secureRandom) {
    ByteArrayOutputStream concatenated = new ByteArrayOutputStream();
    for (UuidCiphertext member : groupMembers) {
      try {
        concatenated.write(member.getInternalContentsForJNI());
      } catch (IOException e) {
        // ByteArrayOutputStream should never fail.
        throw new AssertionError(e);
      }
    }

    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.GroupSendCredentialResponse_IssueDeterministic(
            concatenated.toByteArray(),
            requestingUser.getInternalContentsForJNI(),
            expiration.getEpochSecond(),
            params.getInternalContentsForJNI(),
            random);

    try {
      return new GroupSendCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public GroupSendCredential receive(
      List<ServiceId> groupMembers,
      ServiceId.Aci localUser,
      ServerPublicParams serverParams,
      GroupSecretParams groupParams)
      throws VerificationFailedException {
    return receive(groupMembers, localUser, Instant.now(), serverParams, groupParams);
  }

  public GroupSendCredential receive(
      List<ServiceId> groupMembers,
      ServiceId.Aci localUser,
      Instant now,
      ServerPublicParams serverParams,
      GroupSecretParams groupParams)
      throws VerificationFailedException {
    byte[] newContents =
        Native.GroupSendCredentialResponse_Receive(
            getInternalContentsForJNI(),
            ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
            localUser.toServiceIdFixedWidthBinary(),
            now.getEpochSecond(),
            serverParams.getInternalContentsForJNI(),
            groupParams.getInternalContentsForJNI());

    try {
      return new GroupSendCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}

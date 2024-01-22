//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groupsend;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

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

/**
 * The issuance of a credential indicating membership in a group, based on the set of <em>other</em>
 * users in the group with you.
 *
 * <p>Follows the usual zkgroup pattern of "issue response -> receive response -> present credential
 * -> verify presentation".
 *
 * @see GroupSendCredential
 * @see GroupSendCredentialPresentation
 */
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

  /**
   * Issues a new credential stating that {@code requestingUser} is a member of a group containing
   * {@code groupMembers}.
   *
   * <p>{@code groupMembers} should include {@code requestingUser} as well.
   */
  public static GroupSendCredentialResponse issueCredential(
      List<UuidCiphertext> groupMembers, UuidCiphertext requestingUser, ServerSecretParams params) {
    return issueCredential(
        groupMembers, requestingUser, defaultExpiration(), params, new SecureRandom());
  }

  /**
   * Issues a new credential stating that {@code requestingUser} is a member of a group containing
   * {@code groupMembers}, with an explicitly-chosen expiration.
   *
   * <p>{@code groupMembers} should include {@code requestingUser} as well. {@code expiration} must
   * be day-aligned as a protection against fingerprinting by the issuing server.
   */
  public static GroupSendCredentialResponse issueCredential(
      List<UuidCiphertext> groupMembers,
      UuidCiphertext requestingUser,
      Instant expiration,
      ServerSecretParams params,
      SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.GroupSendCredentialResponse_IssueDeterministic(
            UuidCiphertext.serializeAndConcatenate(groupMembers),
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

  /**
   * Receives, validates, and extracts the credential from a response.
   *
   * <p>Note that the {@code receive} operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, {@link
   * #receive(List, UuidCiphertext, ServerPublicParams, GroupSecretParams)} will be
   * <em>significantly</em> faster; if you don't, this method is faster than generating the
   * ciphertexts and throwing them away afterwards.
   *
   * <p>{@code localUser} should be included in {@code groupMembers}.
   *
   * @throws VerificationFailedException if the credential is not valid for any reason
   */
  public GroupSendCredential receive(
      List<ServiceId> groupMembers,
      ServiceId.Aci localUser,
      ServerPublicParams serverParams,
      GroupSecretParams groupParams)
      throws VerificationFailedException {
    return receive(groupMembers, localUser, Instant.now(), serverParams, groupParams);
  }

  /**
   * Receives, validates, and extracts the credential from a response, assuming a specific current
   * time.
   *
   * <p>This should only be used for testing purposes.
   *
   * @see #receive(List, ServiceId.Aci, ServerPublicParams, GroupSecretParams)
   */
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

  /**
   * Receives, validates, and extracts the credential from a response.
   *
   * <p>Note that the {@code receive} operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, this
   * method will be <em>significantly</em> faster; if you don't, {@link #receive(List,
   * ServiceId.Aci, ServerPublicParams, GroupSecretParams)} is faster than generating the
   * ciphertexts and throwing them away afterwards.
   *
   * <p>{@code localUser} should be included in {@code groupMembers}.
   *
   * @throws VerificationFailedException if the credential is not valid for any reason
   */
  public GroupSendCredential receive(
      List<UuidCiphertext> groupMembers,
      UuidCiphertext localUser,
      ServerPublicParams serverParams,
      GroupSecretParams groupParams)
      throws VerificationFailedException {
    return receive(groupMembers, localUser, Instant.now(), serverParams, groupParams);
  }

  /**
   * Receives, validates, and extracts the credential from a response, assuming a specific current
   * time.
   *
   * <p>This should only be used for testing purposes.
   *
   * @see #receive(List, UuidCiphertext, ServerPublicParams, GroupSecretParams)
   */
  public GroupSendCredential receive(
      List<UuidCiphertext> groupMembers,
      UuidCiphertext localUser,
      Instant now,
      ServerPublicParams serverParams,
      GroupSecretParams groupParams)
      throws VerificationFailedException {
    byte[] newContents =
        Native.GroupSendCredentialResponse_ReceiveWithCiphertexts(
            getInternalContentsForJNI(),
            UuidCiphertext.serializeAndConcatenate(groupMembers),
            localUser.getInternalContentsForJNI(),
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

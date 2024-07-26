//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groupsend;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/**
 * A set of endorsements of the members in a group, along with a proof of their validity.
 *
 * <p>Issued by the group server based on the group's member ciphertexts. The endorsements will
 * eventually be verified by the chat server in the form of {@link GroupSendFullToken}s. See {@link
 * GroupSendEndorsement} for a full description of the endorsement flow from the client's
 * perspective.
 */
public final class GroupSendEndorsementsResponse extends ByteArray {
  public GroupSendEndorsementsResponse(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.GroupSendEndorsementsResponse_CheckValidContents(contents));
  }

  /**
   * Issues a new set of endorsements for {@code groupMembers}.
   *
   * <p>{@code groupMembers} should include {@code requestingUser} as well.
   */
  public static GroupSendEndorsementsResponse issue(
      Collection<UuidCiphertext> groupMembers, GroupSendDerivedKeyPair keyPair) {
    return issue(groupMembers, keyPair, new SecureRandom());
  }

  /**
   * Issues a new set of endorsements for {@code groupMembers}.
   *
   * <p>{@code groupMembers} should include {@code requestingUser} as well.
   */
  public static GroupSendEndorsementsResponse issue(
      Collection<UuidCiphertext> groupMembers,
      GroupSendDerivedKeyPair keyPair,
      SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        filterExceptions(
            () ->
                Native.GroupSendEndorsementsResponse_IssueDeterministic(
                    UuidCiphertext.serializeAndConcatenate(groupMembers),
                    keyPair.getInternalContentsForJNI(),
                    random));
    return filterExceptions(() -> new GroupSendEndorsementsResponse(newContents));
  }

  /** Returns the expiration for the contained endorsements. */
  public Instant getExpiration() {
    return Instant.ofEpochSecond(
        Native.GroupSendEndorsementsResponse_GetExpiration(getInternalContentsForJNI()));
  }

  /**
   * A collection of endorsements known to be valid.
   *
   * <p>The result of the {@code receive} operations on {@link GroupSendEndorsementsResponse}.
   * Contains an endorsement for each member of the group, in the same order they were originally
   * provided, plus a combined endorsement for "everyone but me", intended for multi-recipient
   * sends.
   */
  public record ReceivedEndorsements(
      List<GroupSendEndorsement> endorsements, GroupSendEndorsement combinedEndorsement) {}

  /**
   * Receives, validates, and extracts the endorsements from a response.
   *
   * <p>Note that the {@code receive} operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, {@link
   * #receive(List, UuidCiphertext, ServerPublicParams)} should be faster; if you don't, this method
   * is faster than generating the ciphertexts and throwing them away afterwards.
   *
   * <p>{@code localUser} should be included in {@code groupMembers}. {@code groupMembers} uses
   * {@code List} rather than {@code Collection} because the resulting endorsements are returned in
   * the same order, and thus the order of iteration must be fixed.
   *
   * @throws VerificationFailedException if the endorsements are not valid for any reason
   */
  public ReceivedEndorsements receive(
      List<ServiceId> groupMembers,
      ServiceId.Aci localUser,
      GroupSecretParams groupParams,
      ServerPublicParams serverParams)
      throws VerificationFailedException {
    return receive(groupMembers, localUser, Instant.now(), groupParams, serverParams);
  }

  /**
   * Receives, validates, and extracts the endorsements from a response, assuming a specific current
   * time.
   *
   * <p>This should only be used for testing purposes.
   *
   * @see #receive(List, ServiceId.Aci, GroupSecretParams, ServerPublicParams)
   */
  public ReceivedEndorsements receive(
      List<ServiceId> groupMembers,
      ServiceId.Aci localUser,
      Instant now,
      GroupSecretParams groupParams,
      ServerPublicParams serverPublicParams)
      throws VerificationFailedException {
    byte[][] endorsementContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                serverPublicParams.guardedMapChecked(
                    (publicParams) ->
                        Native.GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds(
                            getInternalContentsForJNI(),
                            ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
                            localUser.toServiceIdFixedWidthBinary(),
                            now.getEpochSecond(),
                            groupParams.getInternalContentsForJNI(),
                            publicParams)));

    List<GroupSendEndorsement> endorsements = new ArrayList<>(endorsementContents.length - 1);
    for (int i = 0; i < endorsementContents.length - 1; ++i) {
      // Normally we don't notice the cost of validating just-created zkgroup objects,
      // but in this case we may have up to 1000 of these. Let's assume they're created correctly.
      endorsements.add(
          new GroupSendEndorsement(endorsementContents[i], ByteArray.UNCHECKED_AND_UNCLONED));
    }
    GroupSendEndorsement combinedEndorsement =
        new GroupSendEndorsement(
            endorsementContents[endorsementContents.length - 1], ByteArray.UNCHECKED_AND_UNCLONED);
    return new ReceivedEndorsements(endorsements, combinedEndorsement);
  }

  /**
   * Receives, validates, and extracts the endorsements from a response.
   *
   * <p>Note that the {@code receive} operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, this
   * method should be faster; if you don't, {@link #receive(List, ServiceId.Aci, GroupSecretParams,
   * ServerPublicParams)} is faster than generating the ciphertexts and throwing them away
   * afterwards.
   *
   * <p>{@code localUser} should be included in {@code groupMembers}. {@code groupMembers} uses
   * {@code List} rather than {@code Collection} because the resulting endorsements are returned in
   * the same order, and thus the order of iteration must be fixed.
   *
   * @throws VerificationFailedException if the endorsements are not valid for any reason
   */
  public ReceivedEndorsements receive(
      List<UuidCiphertext> groupMembers, UuidCiphertext localUser, ServerPublicParams serverParams)
      throws VerificationFailedException {
    return receive(groupMembers, localUser, Instant.now(), serverParams);
  }

  /**
   * Receives, validates, and extracts the endorsements from a response, assuming a specific current
   * time.
   *
   * <p>This should only be used for testing purposes.
   *
   * @see #receive(List, UuidCiphertext, ServerPublicParams)
   */
  public ReceivedEndorsements receive(
      List<UuidCiphertext> groupMembers,
      UuidCiphertext localUser,
      Instant now,
      ServerPublicParams serverPublicParams)
      throws VerificationFailedException {
    byte[][] endorsementContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                serverPublicParams.guardedMapChecked(
                    (publicParams) ->
                        Native.GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts(
                            getInternalContentsForJNI(),
                            UuidCiphertext.serializeAndConcatenate(groupMembers),
                            localUser.getInternalContentsForJNI(),
                            now.getEpochSecond(),
                            publicParams)));

    List<GroupSendEndorsement> endorsements = new ArrayList<>(endorsementContents.length - 1);
    for (int i = 0; i < endorsementContents.length - 1; ++i) {
      // Normally we don't notice the cost of validating just-created zkgroup objects,
      // but in this case we may have up to 1000 of these. Let's assume they're created correctly.
      endorsements.add(
          new GroupSendEndorsement(endorsementContents[i], ByteArray.UNCHECKED_AND_UNCLONED));
    }
    GroupSendEndorsement combinedEndorsement =
        new GroupSendEndorsement(
            endorsementContents[endorsementContents.length - 1], ByteArray.UNCHECKED_AND_UNCLONED);
    return new ReceivedEndorsements(endorsements, combinedEndorsement);
  }
}

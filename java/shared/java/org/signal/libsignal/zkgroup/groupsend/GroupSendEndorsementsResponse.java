//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groupsend;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
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
      List<UuidCiphertext> groupMembers, GroupSendDerivedKeyPair keyPair) {
    return issue(groupMembers, keyPair, new SecureRandom());
  }

  /**
   * Issues a new set of endorsements for {@code groupMembers}.
   *
   * <p>{@code groupMembers} should include {@code requestingUser} as well.
   */
  public static GroupSendEndorsementsResponse issue(
      List<UuidCiphertext> groupMembers,
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
  public class ReceivedEndorsements {
    /**
     * One endorsement per member of the group, in the same order the members were originally
     * provided.
     */
    public List<GroupSendEndorsement> endorsements;

    /** An endorsement for everyone in the group but the local user, for multi-recipient sends. */
    public GroupSendEndorsement combinedEndorsement;

    <T> ReceivedEndorsements(
        List<GroupSendEndorsement> endorsements, List<T> members, T localMember) {
      this.endorsements = endorsements;

      int memberCount = members.size();
      assert endorsements.size() == memberCount;

      ByteBuffer[] buffers = new ByteBuffer[memberCount - 1];
      int nextOffset = 0;
      for (int i = 0; i < memberCount; ++i) {
        if (members.get(i).equals(localMember)) {
          continue;
        }
        if (nextOffset == memberCount - 1) {
          throw new IllegalArgumentException("member list did not contain the local user");
        }
        byte[] nextEndorsementRaw = endorsements.get(i).getInternalContentsForJNI();
        buffers[nextOffset] = ByteBuffer.allocateDirect(nextEndorsementRaw.length);
        buffers[nextOffset].put(nextEndorsementRaw);
        ++nextOffset;
      }

      byte[] rawCombinedEndorsement = Native.GroupSendEndorsement_Combine(buffers);
      this.combinedEndorsement =
          filterExceptions(() -> new GroupSendEndorsement(rawCombinedEndorsement));
    }
  }

  /**
   * Receives, validates, and extracts the endorsements from a response.
   *
   * <p>Note that the {@code receive} operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, {@link
   * #receive(List, UuidCiphertext, ServerPublicParams)} will be <em>significantly</em> faster; if
   * you don't, this method is faster than generating the ciphertexts and throwing them away
   * afterwards.
   *
   * <p>{@code localUser} should be included in {@code groupMembers}.
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
      ServerPublicParams serverParams)
      throws VerificationFailedException {
    byte[][] endorsementContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                (byte[][])
                    Native.GroupSendEndorsementsResponse_ReceiveWithServiceIds(
                        getInternalContentsForJNI(),
                        ServiceId.toConcatenatedFixedWidthBinary(groupMembers),
                        now.getEpochSecond(),
                        groupParams.getInternalContentsForJNI(),
                        serverParams.getInternalContentsForJNI()));

    List<GroupSendEndorsement> endorsements = new ArrayList<>(endorsementContents.length);
    for (byte[] contents : endorsementContents) {
      endorsements.add(filterExceptions(() -> new GroupSendEndorsement(contents)));
    }
    return new ReceivedEndorsements(endorsements, groupMembers, localUser);
  }

  /**
   * Receives, validates, and extracts the endorsements from a response.
   *
   * <p>Note that the {@code receive} operation is provided for both {@link ServiceId}s and {@link
   * UuidCiphertext}s. If you already have the ciphertexts for the group members available, this
   * method will be <em>significantly</em> faster; if you don't, {@link #receive(List,
   * ServiceId.Aci, GroupSecretParams, ServerPublicParams)} is faster than generating the
   * ciphertexts and throwing them away afterwards.
   *
   * <p>{@code localUser} should be included in {@code groupMembers}.
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
      ServerPublicParams serverParams)
      throws VerificationFailedException {
    byte[][] endorsementContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                (byte[][])
                    Native.GroupSendEndorsementsResponse_ReceiveWithCiphertexts(
                        getInternalContentsForJNI(),
                        UuidCiphertext.serializeAndConcatenate(groupMembers),
                        now.getEpochSecond(),
                        serverParams.getInternalContentsForJNI()));

    List<GroupSendEndorsement> endorsements = new ArrayList<>(endorsementContents.length);
    for (byte[] contents : endorsementContents) {
      endorsements.add(filterExceptions(() -> new GroupSendEndorsement(contents)));
    }
    return new ReceivedEndorsements(endorsements, groupMembers, localUser);
  }
}

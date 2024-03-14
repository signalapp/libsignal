//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.integrationtests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.Test;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.zkgroup.SecureRandomTest;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.ClientZkGroupCipher;
import org.signal.libsignal.zkgroup.groups.GroupMasterKey;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.groupsend.GroupSendDerivedKeyPair;
import org.signal.libsignal.zkgroup.groupsend.GroupSendEndorsement;
import org.signal.libsignal.zkgroup.groupsend.GroupSendEndorsementsResponse;
import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken;

public final class GroupSendEndorsementTest extends SecureRandomTest {
  private static final byte[] TEST_ARRAY_32 =
      Hex.fromStringCondensedAssert(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

  private static final byte[] TEST_ARRAY_32_1 =
      Hex.fromStringCondensedAssert(
          "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283");

  private static final byte[] TEST_ARRAY_32_2 =
      Hex.fromStringCondensedAssert(
          "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7");

  @Test
  public void testGroupSendIntegration() throws Exception {
    ServiceId.Aci aliceServiceId =
        ServiceId.Aci.parseFromString("38381c3b-2606-4ca7-9310-7cb927f2ab4a");
    ServiceId.Aci bobServiceId =
        ServiceId.Aci.parseFromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1");
    ServiceId.Aci eveServiceId =
        ServiceId.Aci.parseFromString("3f0f4734-e331-4434-bd4f-6d8f6ea6dcc7");
    ServiceId.Aci malloryServiceId =
        ServiceId.Aci.parseFromString("5d088142-6fd7-4dbd-af00-fdda1b3ce988");

    // SERVER
    // Generate keys
    ServerSecretParams serverSecretParams =
        ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // CLIENT
    // Generate keys
    GroupMasterKey masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    // Set up group state
    UuidCiphertext aliceCiphertext =
        new ClientZkGroupCipher(groupSecretParams).encrypt(aliceServiceId);
    List<UuidCiphertext> groupCiphertexts =
        Stream.of(aliceServiceId, bobServiceId, eveServiceId, malloryServiceId)
            .map((next) -> new ClientZkGroupCipher(groupSecretParams).encrypt(next))
            .collect(Collectors.toList());

    // SERVER
    // Issue endorsements
    Instant expiration = Instant.now().truncatedTo(ChronoUnit.DAYS).plus(2, ChronoUnit.DAYS);
    GroupSendDerivedKeyPair keyPair =
        GroupSendDerivedKeyPair.forExpiration(expiration, serverSecretParams);
    GroupSendEndorsementsResponse response =
        GroupSendEndorsementsResponse.issue(groupCiphertexts, keyPair);

    // CLIENT
    // Gets stored endorsements
    GroupSendEndorsementsResponse.ReceivedEndorsements receivedEndorsements =
        response.receive(
            Arrays.asList(aliceServiceId, bobServiceId, eveServiceId, malloryServiceId),
            aliceServiceId,
            groupSecretParams,
            serverPublicParams);

    assertThrows(
        "missing local user",
        AssertionError.class,
        () ->
            response.receive(
                Arrays.asList(bobServiceId, eveServiceId, malloryServiceId),
                aliceServiceId,
                groupSecretParams,
                serverPublicParams));
    assertThrows(
        "missing another user",
        VerificationFailedException.class,
        () ->
            response.receive(
                Arrays.asList(aliceServiceId, eveServiceId, malloryServiceId),
                aliceServiceId,
                groupSecretParams,
                serverPublicParams));

    // Try receive with ciphertexts instead.
    {
      GroupSendEndorsementsResponse.ReceivedEndorsements repeatReceivedEndorsements =
          response.receive(groupCiphertexts, aliceCiphertext, serverPublicParams);
      assertEquals(receivedEndorsements.endorsements(), repeatReceivedEndorsements.endorsements());
      assertEquals(
          receivedEndorsements.combinedEndorsement(),
          repeatReceivedEndorsements.combinedEndorsement());

      assertThrows(
          "missing local user",
          AssertionError.class,
          () ->
              response.receive(
                  groupCiphertexts.stream().skip(1).collect(Collectors.toList()),
                  aliceCiphertext,
                  serverPublicParams));
      assertThrows(
          "missing another user",
          VerificationFailedException.class,
          () ->
              response.receive(
                  groupCiphertexts.stream().limit(3).collect(Collectors.toList()),
                  aliceCiphertext,
                  serverPublicParams));
    }

    GroupSendEndorsement.Token combinedToken =
        receivedEndorsements.combinedEndorsement().toToken(groupSecretParams);
    GroupSendFullToken fullCombinedToken = combinedToken.toFullToken(response.getExpiration());

    // SERVER
    // Verify token
    GroupSendDerivedKeyPair verifyKey =
        GroupSendDerivedKeyPair.forExpiration(
            fullCombinedToken.getExpiration(), serverSecretParams);

    fullCombinedToken.verify(
        Arrays.asList(bobServiceId, eveServiceId, malloryServiceId), verifyKey);
    fullCombinedToken.verify(
        Arrays.asList(bobServiceId, eveServiceId, malloryServiceId),
        Instant.now().plus(1, ChronoUnit.HOURS),
        verifyKey);

    assertThrows(
        "included extra user",
        VerificationFailedException.class,
        () ->
            fullCombinedToken.verify(
                Arrays.asList(aliceServiceId, bobServiceId, eveServiceId, malloryServiceId),
                verifyKey));
    assertThrows(
        "missing user",
        VerificationFailedException.class,
        () -> fullCombinedToken.verify(Arrays.asList(eveServiceId, malloryServiceId), verifyKey));

    assertThrows(
        "expired",
        VerificationFailedException.class,
        () ->
            fullCombinedToken.verify(
                Arrays.asList(bobServiceId, eveServiceId, malloryServiceId),
                Instant.now()
                    .truncatedTo(ChronoUnit.DAYS)
                    .plus(2, ChronoUnit.DAYS)
                    .plus(1, ChronoUnit.SECONDS),
                verifyKey));

    // Excluding a user
    {
      // CLIENT
      GroupSendEndorsement everybodyButMallory =
          receivedEndorsements
              .combinedEndorsement()
              .byRemoving(receivedEndorsements.endorsements().get(3));
      GroupSendFullToken fullEverybodyButMalloryToken =
          everybodyButMallory.toFullToken(groupSecretParams, response.getExpiration());

      // SERVER
      GroupSendDerivedKeyPair everybodyButMalloryKey =
          GroupSendDerivedKeyPair.forExpiration(
              fullEverybodyButMalloryToken.getExpiration(), serverSecretParams);

      fullEverybodyButMalloryToken.verify(
          Arrays.asList(bobServiceId, eveServiceId), everybodyButMalloryKey);
    }

    // Custom combine
    {
      // CLIENT
      GroupSendEndorsement bobAndEve =
          GroupSendEndorsement.combine(
              Arrays.asList(
                  receivedEndorsements.endorsements().get(1),
                  receivedEndorsements.endorsements().get(2)));
      GroupSendFullToken fullBobAndEveToken =
          bobAndEve.toFullToken(groupSecretParams, response.getExpiration());

      // SERVER
      GroupSendDerivedKeyPair bobAndEveKey =
          GroupSendDerivedKeyPair.forExpiration(
              fullBobAndEveToken.getExpiration(), serverSecretParams);

      fullBobAndEveToken.verify(Arrays.asList(bobServiceId, eveServiceId), bobAndEveKey);
    }

    // Single-user
    {
      // CLIENT
      GroupSendEndorsement bobEndorsement = receivedEndorsements.endorsements().get(1);
      GroupSendFullToken fullBobToken =
          bobEndorsement.toFullToken(groupSecretParams, response.getExpiration());

      // SERVER
      GroupSendDerivedKeyPair bobKey =
          GroupSendDerivedKeyPair.forExpiration(fullBobToken.getExpiration(), serverSecretParams);

      fullBobToken.verify(Arrays.asList(bobServiceId), bobKey);
    }
  }

  @Test
  public void test1000PersonGroup() throws Exception {
    // SERVER
    // Generate keys
    ServerSecretParams serverSecretParams =
        ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // CLIENT
    // Generate keys
    GroupMasterKey masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    // Set up group state
    ServiceId.Aci[] members = new ServiceId.Aci[1000];
    for (int i = 0; i < members.length; ++i) {
      members[i] = new ServiceId.Aci(UUID.randomUUID());
    }

    UuidCiphertext[] encryptedMembers = new UuidCiphertext[members.length];
    final ClientZkGroupCipher cipher = new ClientZkGroupCipher(groupSecretParams);
    for (int i = 0; i < members.length; ++i) {
      encryptedMembers[i] = cipher.encrypt(members[i]);
    }

    // SERVER
    // Issue endorsements
    Instant expiration = Instant.now().truncatedTo(ChronoUnit.DAYS).plus(2, ChronoUnit.DAYS);
    GroupSendDerivedKeyPair keyPair =
        GroupSendDerivedKeyPair.forExpiration(expiration, serverSecretParams);
    GroupSendEndorsementsResponse response =
        GroupSendEndorsementsResponse.issue(Arrays.asList(encryptedMembers), keyPair);

    // CLIENT
    // Gets stored endorsements
    // Just don't crash (this did crash on a lower-end 32-bit phone once).
    response.receive(Arrays.asList(members), members[0], groupSecretParams, serverPublicParams);
    response.receive(Arrays.asList(encryptedMembers), encryptedMembers[0], serverPublicParams);
  }

  @Test
  public void test1PersonGroup() throws Exception {
    // SERVER
    // Generate keys
    ServerSecretParams serverSecretParams =
        ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // CLIENT
    // Generate keys
    GroupMasterKey masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    // Set up group state
    ServiceId.Aci member = new ServiceId.Aci(UUID.randomUUID());
    UuidCiphertext encryptedMember = new ClientZkGroupCipher(groupSecretParams).encrypt(member);

    // SERVER
    // Issue endorsements
    Instant expiration = Instant.now().truncatedTo(ChronoUnit.DAYS).plus(2, ChronoUnit.DAYS);
    GroupSendDerivedKeyPair keyPair =
        GroupSendDerivedKeyPair.forExpiration(expiration, serverSecretParams);
    GroupSendEndorsementsResponse response =
        GroupSendEndorsementsResponse.issue(Arrays.asList(encryptedMember), keyPair);

    // CLIENT
    // Gets stored endorsements
    // Just don't crash.
    response.receive(Arrays.asList(member), member, groupSecretParams, serverPublicParams);
    response.receive(Arrays.asList(encryptedMember), encryptedMember, serverPublicParams);
  }
}

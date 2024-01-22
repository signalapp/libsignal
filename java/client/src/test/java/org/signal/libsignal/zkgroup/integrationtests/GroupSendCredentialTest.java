//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.integrationtests;

import static org.junit.Assert.assertThrows;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
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
import org.signal.libsignal.zkgroup.groupsend.GroupSendCredential;
import org.signal.libsignal.zkgroup.groupsend.GroupSendCredentialPresentation;
import org.signal.libsignal.zkgroup.groupsend.GroupSendCredentialResponse;

public final class GroupSendCredentialTest extends SecureRandomTest {
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
    // Issue credential
    GroupSendCredentialResponse response =
        GroupSendCredentialResponse.issueCredential(
            groupCiphertexts, aliceCiphertext, serverSecretParams);

    // CLIENT
    // Gets stored credential
    GroupSendCredential credential =
        response.receive(
            Arrays.asList(aliceServiceId, bobServiceId, eveServiceId, malloryServiceId),
            aliceServiceId,
            serverPublicParams,
            groupSecretParams);

    assertThrows(
        VerificationFailedException.class,
        () ->
            response.receive(
                Arrays.asList(aliceServiceId, bobServiceId, eveServiceId, malloryServiceId),
                bobServiceId,
                serverPublicParams,
                groupSecretParams));
    assertThrows(
        VerificationFailedException.class,
        () ->
            response.receive(
                Arrays.asList(bobServiceId, eveServiceId, malloryServiceId),
                aliceServiceId,
                serverPublicParams,
                groupSecretParams));
    assertThrows(
        VerificationFailedException.class,
        () ->
            response.receive(
                Arrays.asList(aliceServiceId, eveServiceId, malloryServiceId),
                aliceServiceId,
                serverPublicParams,
                groupSecretParams));

    // Try receive with ciphertexts instead.
    response.receive(groupCiphertexts, aliceCiphertext, serverPublicParams, groupSecretParams);

    assertThrows(
        VerificationFailedException.class,
        () ->
            response.receive(
                groupCiphertexts, groupCiphertexts.get(1), serverPublicParams, groupSecretParams));
    assertThrows(
        VerificationFailedException.class,
        () ->
            response.receive(
                groupCiphertexts.stream().skip(1).collect(Collectors.toList()),
                aliceCiphertext,
                serverPublicParams,
                groupSecretParams));
    assertThrows(
        VerificationFailedException.class,
        () ->
            response.receive(
                groupCiphertexts.stream().limit(3).collect(Collectors.toList()),
                aliceCiphertext,
                serverPublicParams,
                groupSecretParams));

    GroupSendCredentialPresentation presentation =
        credential.present(serverPublicParams, createSecureRandom(TEST_ARRAY_32_2));

    // SERVER
    // Verify presentation
    presentation.verify(
        Arrays.asList(bobServiceId, eveServiceId, malloryServiceId), serverSecretParams);
    presentation.verify(
        Arrays.asList(bobServiceId, eveServiceId, malloryServiceId),
        Instant.now().plus(1, ChronoUnit.HOURS),
        serverSecretParams);

    assertThrows(
        VerificationFailedException.class,
        () ->
            presentation.verify(
                Arrays.asList(aliceServiceId, bobServiceId, eveServiceId, malloryServiceId),
                serverSecretParams));
    assertThrows(
        VerificationFailedException.class,
        () ->
            presentation.verify(Arrays.asList(eveServiceId, malloryServiceId), serverSecretParams));

    // Credential should definitely be expired after two full days.
    assertThrows(
        VerificationFailedException.class,
        () ->
            presentation.verify(
                Arrays.asList(bobServiceId, eveServiceId, malloryServiceId),
                Instant.now()
                    .truncatedTo(ChronoUnit.DAYS)
                    .plus(2, ChronoUnit.DAYS)
                    .plus(1, ChronoUnit.SECONDS),
                serverSecretParams));
  }

  @Test
  public void testEmptyCredential() throws Exception {
    ServiceId.Aci aliceServiceId =
        ServiceId.Aci.parseFromString("38381c3b-2606-4ca7-9310-7cb927f2ab4a");

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

    // SERVER
    // Issue credential
    GroupSendCredentialResponse response =
        GroupSendCredentialResponse.issueCredential(
            Arrays.asList(aliceCiphertext), aliceCiphertext, serverSecretParams);

    // CLIENT
    // Gets stored credential
    response.receive(
        Arrays.asList(aliceServiceId), aliceServiceId, serverPublicParams, groupSecretParams);
  }
}

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.Assert;
import org.junit.Test;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.zkgroup.avatars.*;

/**
 * End-to-end test of the avatar upload credential through the JNI bridge.
 *
 * <p>This also doubles as a worked reference for the server team: it shows the full
 * issue/receive/present/verify lifecycle from both the client and server sides.
 */
public final class AvatarUploadCredentialTest extends SecureRandomTest {

  // Chosen randomly.
  private static final Aci TEST_ACI =
      new Aci(UUID.fromString("c0fc16e4-bae5-4343-9f0d-e7ecf4251343"));

  private static final byte[] ZK_CRED_KEY_RANDOM =
      Hex.fromStringCondensedAssert(
          "4242424242424242424242424242424242424242424242424242424242424242");

  private static final byte[] WRONG_ZK_CRED_KEY_RANDOM =
      Hex.fromStringCondensedAssert(
          "9999999999999999999999999999999999999999999999999999999999999999");

  private static final byte[] SERVER_SECRET_RANDOM =
      Hex.fromStringCondensedAssert(
          "6987b92bdea075d3f8b42b39d780a5be0bc264874a18e11cac694e4fe28f6cca");

  private static final byte[] CREATE_RANDOM =
      Hex.fromStringCondensedAssert(
          "657e7a2ac9dd981b789c9b2fbcdfbbe46cb6230c7a2c67c1be3472cb006463e2");

  private static final byte[] ISSUE_RANDOM =
      Hex.fromStringCondensedAssert(
          "8e3f24cb0a7e7614c7b4ab04ba8a145f108c53c4b10a096aa4503ae1e0c9f661");

  private static final byte[] PRESENT_RANDOM =
      Hex.fromStringCondensedAssert(
          "475149b2bdcb6f9bd3a8e3a5d4c6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8");

  private static final long ROTATION_ID = 7L;

  @Test
  public void testAvatarUploadCredentialIntegration()
      throws VerificationFailedException, InvalidInputException {
    // SERVER: generate keys.
    final GenericServerSecretParams serverSecretParams =
        GenericServerSecretParams.generate(createSecureRandom(SERVER_SECRET_RANDOM));
    final GenericServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // CLIENT: generate its long-term ZK credential key pair and (out of band) register the public
    // half with the server.
    final ZkCredentialKeyPair zkCredentialKeyPair =
        ZkCredentialKeyPair.generate(createSecureRandom(ZK_CRED_KEY_RANDOM));
    final ZkCredentialPublicKey zkCredentialKeyPublic = zkCredentialKeyPair.getPublicKey();

    // CLIENT: build a request.
    AvatarUploadCredentialRequestContext context =
        AvatarUploadCredentialRequestContext.create(
            TEST_ACI, zkCredentialKeyPair, ROTATION_ID, createSecureRandom(CREATE_RANDOM));
    AvatarUploadCredentialRequest request = context.getRequest();

    // Round-tripping the request through serialize() must preserve it.
    Assert.assertArrayEquals(
        request.serialize(), new AvatarUploadCredentialRequest(request.serialize()).serialize());

    // SERVER: authenticate the ACI, look up its ZK credential key, and issue.
    final Instant timestamp = Instant.now().truncatedTo(ChronoUnit.DAYS);
    AvatarUploadCredentialResponse response =
        request.issueCredential(
            TEST_ACI,
            zkCredentialKeyPublic,
            ROTATION_ID,
            timestamp,
            serverSecretParams,
            createSecureRandom(ISSUE_RANDOM));

    // CLIENT: verify and unblind the credential. The client passes its current wall-clock time;
    // libsignal checks that the credential's redemption_time (chosen by the server, carried in
    // `response`) is day-aligned and inside the redemption window relative to `now`.
    AvatarUploadCredential credential =
        context.receiveResponse(response, timestamp, serverPublicParams);

    // The client can read back the redemption time the issuing server chose.
    Assert.assertEquals(timestamp, credential.getRedemptionTime());

    AvatarUploadCredential credentialDefaultTime =
        context.receiveResponse(response, serverPublicParams);
    Assert.assertArrayEquals(credential.serialize(), credentialDefaultTime.serialize());

    // CLIENT: present the credential.
    AvatarUploadCredentialPresentation presentation =
        credential.present(serverPublicParams, createSecureRandom(PRESENT_RANDOM));

    // The revealed commitment Cm must match between the credential and its presentation.
    Assert.assertArrayEquals(credential.getCommitment(), presentation.getCommitment());
    Assert.assertEquals(timestamp, presentation.getRedemptionTime());

    // SERVER: verify the presentation across the redemption window.
    presentation.verify(timestamp, serverSecretParams);
    presentation.verify(timestamp.plus(1, ChronoUnit.DAYS), serverSecretParams);

    Assert.assertThrows(
        "Credential should be expired more than 2 days after redemption time",
        VerificationFailedException.class,
        () ->
            presentation.verify(
                timestamp.plus(2, ChronoUnit.DAYS).plusSeconds(1), serverSecretParams));

    Assert.assertThrows(
        "Credential should be invalid before its redemption time",
        VerificationFailedException.class,
        () ->
            presentation.verify(
                timestamp.minus(1, ChronoUnit.DAYS).minusSeconds(1), serverSecretParams));
  }

  @Test
  public void testIssuanceRejectsWrongAci() {
    final GenericServerSecretParams serverSecretParams =
        GenericServerSecretParams.generate(createSecureRandom(SERVER_SECRET_RANDOM));

    final ZkCredentialKeyPair zkCredentialKeyPair =
        ZkCredentialKeyPair.generate(createSecureRandom(ZK_CRED_KEY_RANDOM));
    final ZkCredentialPublicKey zkCredentialKeyPublic = zkCredentialKeyPair.getPublicKey();

    AvatarUploadCredentialRequestContext context =
        AvatarUploadCredentialRequestContext.create(
            TEST_ACI, zkCredentialKeyPair, ROTATION_ID, createSecureRandom(CREATE_RANDOM));
    AvatarUploadCredentialRequest request = context.getRequest();

    final Aci wrongAci = new Aci(UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
    final Instant timestamp = Instant.now().truncatedTo(ChronoUnit.DAYS);

    Assert.assertThrows(
        "Issuance should fail when the server checks against a different ACI",
        VerificationFailedException.class,
        () ->
            request.issueCredential(
                wrongAci,
                zkCredentialKeyPublic,
                ROTATION_ID,
                timestamp,
                serverSecretParams,
                createSecureRandom(ISSUE_RANDOM)));
  }

  @Test
  public void testIssuanceRejectsWrongZkCredentialKey() {
    final GenericServerSecretParams serverSecretParams =
        GenericServerSecretParams.generate(createSecureRandom(SERVER_SECRET_RANDOM));

    final ZkCredentialKeyPair zkCredentialKeyPair =
        ZkCredentialKeyPair.generate(createSecureRandom(ZK_CRED_KEY_RANDOM));

    AvatarUploadCredentialRequestContext context =
        AvatarUploadCredentialRequestContext.create(
            TEST_ACI, zkCredentialKeyPair, ROTATION_ID, createSecureRandom(CREATE_RANDOM));
    AvatarUploadCredentialRequest request = context.getRequest();

    // Server has a different ZK credential public key on file for this account.
    final ZkCredentialPublicKey wrongZkCredentialKeyPublic =
        ZkCredentialKeyPair.generate(createSecureRandom(WRONG_ZK_CRED_KEY_RANDOM)).getPublicKey();

    final Instant timestamp = Instant.now().truncatedTo(ChronoUnit.DAYS);

    Assert.assertThrows(
        "Issuance should fail when the server uses a different ZK credential public key",
        VerificationFailedException.class,
        () ->
            request.issueCredential(
                TEST_ACI,
                wrongZkCredentialKeyPublic,
                ROTATION_ID,
                timestamp,
                serverSecretParams,
                createSecureRandom(ISSUE_RANDOM)));
  }

  @Test
  public void testIssuanceRejectsWrongRotationId() {
    final GenericServerSecretParams serverSecretParams =
        GenericServerSecretParams.generate(createSecureRandom(SERVER_SECRET_RANDOM));

    final ZkCredentialKeyPair zkCredentialKeyPair =
        ZkCredentialKeyPair.generate(createSecureRandom(ZK_CRED_KEY_RANDOM));
    final ZkCredentialPublicKey zkCredentialKeyPublic = zkCredentialKeyPair.getPublicKey();

    // Client commits to one rotation ID...
    AvatarUploadCredentialRequestContext context =
        AvatarUploadCredentialRequestContext.create(
            TEST_ACI, zkCredentialKeyPair, ROTATION_ID, createSecureRandom(CREATE_RANDOM));
    AvatarUploadCredentialRequest request = context.getRequest();

    final Instant timestamp = Instant.now().truncatedTo(ChronoUnit.DAYS);

    Assert.assertThrows(
        "Issuance should fail when the server uses a different rotation ID",
        VerificationFailedException.class,
        () ->
            // ...but the server issues against a different one.
            request.issueCredential(
                TEST_ACI,
                zkCredentialKeyPublic,
                ROTATION_ID + 1,
                timestamp,
                serverSecretParams,
                createSecureRandom(ISSUE_RANDOM)));
  }

  @Test
  public void testPublicKeyDerivationIsDeterministic() {
    final ZkCredentialKeyPair a =
        ZkCredentialKeyPair.generate(createSecureRandom(ZK_CRED_KEY_RANDOM));
    final ZkCredentialKeyPair b =
        ZkCredentialKeyPair.generate(createSecureRandom(ZK_CRED_KEY_RANDOM));
    Assert.assertArrayEquals(a.serialize(), b.serialize());
    Assert.assertArrayEquals(a.getPublicKey().serialize(), b.getPublicKey().serialize());
  }
}

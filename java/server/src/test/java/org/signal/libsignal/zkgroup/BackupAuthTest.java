//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import org.junit.Assert;
import org.junit.Test;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.zkgroup.backups.*;

/**
 * Tests the BackupAuthCredential
 *
 * <p>Normally, we'd like to run this test on both android and non-android platforms, but Android 21
 * doesn't have java.util.Base64 and non-android hosts don't have android.util.Base64
 */
public final class BackupAuthTest extends SecureRandomTest {

  private static final UUID TEST_USER_ID = UUID.fromString("e74beed0-e70f-4cfd-abbb-7e3eb333bbac");

  private static final byte[] BACKUP_KEY =
      Hex.fromStringCondensedAssert(
          "f9abbbffa7d424929765aecc84b604633c55ac1bce82e1ee06b79bc9a5629338");

  private static final byte[] SERVER_SECRET_RANDOM =
      Hex.fromStringCondensedAssert(
          "6987b92bdea075d3f8b42b39d780a5be0bc264874a18e11cac694e4fe28f6cca");

  private static final byte[] TEST_ARRAY_32_1 =
      Hex.fromStringCondensedAssert(
          "657e7a2ac9dd981b789c9b2fbcdfbbe46cb6230c7a2c67c1be3472cb006463e2");

  private static final byte[] TEST_ARRAY_32_2 =
      Hex.fromStringCondensedAssert(
          "8e3f24cb0a7e7614c7b4ab04ba8a145f108c53c4b10a096aa4503ae1e0c9f661");

  private static final byte[] SERIALIZED_BACKUP_ID =
      Hex.fromStringCondensedAssert("e3926f11ddd143e6dd0f20bfcb08349e");
  private static final byte[] SERIALIZED_REQUEST_CREDENTIAL =
      Base64.getDecoder()
          .decode(
              "AISCxQa8OsFqphsQPxqtzJk5+jndpE3SJG6bfazQB3994Aersq2yNRgcARBoedBeoEfKIXdty6X7l6+TiPFAqDvojRSO8xaZOpKJOvWSDJIGn6EeMl2jOjx+IQg8d8M0AQ=="
                  .getBytes(StandardCharsets.UTF_8));

  @Test
  public void testCredentialIsDeterministic() throws VerificationFailedException {
    BackupAuthCredentialRequestContext context =
        BackupAuthCredentialRequestContext.create(BACKUP_KEY, TEST_USER_ID);
    BackupAuthCredentialRequest request = context.getRequest();
    Assert.assertArrayEquals(request.serialize(), SERIALIZED_REQUEST_CREDENTIAL);

    GenericServerSecretParams serverSecretParams =
        GenericServerSecretParams.generate(createSecureRandom(SERVER_SECRET_RANDOM));
    Instant timestamp = Instant.now().truncatedTo(ChronoUnit.DAYS);
    BackupAuthCredentialResponse response =
        request.issueCredential(timestamp, 1L, serverSecretParams);

    BackupAuthCredential credential =
        context.receiveResponse(response, serverSecretParams.getPublicParams(), 1L);
    Assert.assertArrayEquals(SERIALIZED_BACKUP_ID, credential.getBackupId());
    Assert.assertArrayEquals(
        SERIALIZED_BACKUP_ID,
        credential.present(serverSecretParams.getPublicParams()).getBackupId());
  }

  @Test
  public void testBackupAuthCredentialIntegration() throws VerificationFailedException {
    final long receiptLevel = 10L;

    // SERVER
    // Generate keys
    final GenericServerSecretParams serverSecretParams =
        GenericServerSecretParams.generate(createSecureRandom(SERVER_SECRET_RANDOM));
    final GenericServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // CLIENT
    BackupAuthCredentialRequestContext context =
        BackupAuthCredentialRequestContext.create(BACKUP_KEY, TEST_USER_ID);
    BackupAuthCredentialRequest request = context.getRequest();

    // SERVER
    // Issue credential
    Instant timestamp = Instant.now().truncatedTo(ChronoUnit.DAYS);
    BackupAuthCredentialResponse response =
        request.issueCredential(
            timestamp, receiptLevel, serverSecretParams, createSecureRandom(TEST_ARRAY_32_1));

    // CLIENT
    // Gets stored credential
    BackupAuthCredential credential =
        context.receiveResponse(response, serverPublicParams, receiptLevel);
    Assert.assertThrows(
        "Wrong receipt level",
        VerificationFailedException.class,
        () -> context.receiveResponse(response, serverPublicParams, receiptLevel + 1));

    // CLIENT
    // Generates a presentation
    final BackupAuthCredentialPresentation presentation =
        credential.present(serverPublicParams, createSecureRandom(TEST_ARRAY_32_2));

    // SERVER
    // Verify presentation
    presentation.verify(serverSecretParams);
    presentation.verify(timestamp.plus(1, ChronoUnit.DAYS), serverSecretParams);
    Assert.assertArrayEquals(credential.getBackupId(), presentation.getBackupId());
    Assert.assertEquals(receiptLevel, presentation.getReceiptLevel());

    Assert.assertThrows(
        "Credential should be expired after 2 days",
        VerificationFailedException.class,
        () ->
            presentation.verify(
                timestamp.plus(2, ChronoUnit.DAYS).plusSeconds(1), serverSecretParams));

    Assert.assertThrows(
        "Future credential should be invalid",
        VerificationFailedException.class,
        () ->
            presentation.verify(
                timestamp.minus(1, ChronoUnit.DAYS).minusSeconds(1), serverSecretParams));
  }
}

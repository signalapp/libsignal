//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.integrationtests;

import java.io.UnsupportedEncodingException;
import org.junit.Test;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.SecureRandomTest;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.calllinks.CallLinkPublicParams;
import org.signal.libsignal.zkgroup.calllinks.CallLinkSecretParams;
import org.signal.libsignal.zkgroup.calllinks.CallLinkAuthCredential;
import org.signal.libsignal.zkgroup.calllinks.CallLinkAuthCredentialPresentation;
import org.signal.libsignal.zkgroup.calllinks.CallLinkAuthCredentialResponse;
import org.signal.libsignal.zkgroup.calllinks.CreateCallLinkCredential;
import org.signal.libsignal.zkgroup.calllinks.CreateCallLinkCredentialPresentation;
import org.signal.libsignal.zkgroup.calllinks.CreateCallLinkCredentialRequest;
import org.signal.libsignal.zkgroup.calllinks.CreateCallLinkCredentialRequestContext;
import org.signal.libsignal.zkgroup.calllinks.CreateCallLinkCredentialResponse;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

public final class CallLinksTest extends SecureRandomTest {

  private static final Aci    TEST_USER_ID    = new Aci(UUID.fromString("00010203-0405-0607-0809-0a0b0c0d0e0f"));

  private static final byte[] TEST_ARRAY_32   = Hex.fromStringCondensedAssert("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

  private static final byte[] TEST_ARRAY_32_1 = Hex.fromStringCondensedAssert("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283");

  private static final byte[] TEST_ARRAY_32_2 = Hex.fromStringCondensedAssert("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7");

  private static final byte[] TEST_ARRAY_32_3 = { 1, 2, 3, 4, 5, 6, 7, 8, 9,
      10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
      28, 29, 30, 31, 32 };

  private static final byte[] TEST_ARRAY_32_4 = { 
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33};

  private static final byte[] TEST_ARRAY_32_5 = Hex.fromStringCondensedAssert("030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122");

  // 32 bytes of 0xFF is an invalid Ristretto point, so this should invalidate all the
  // the serialized zkgroup structures, since almost everything contains a Ristretto point
  private static final byte[] makeBadArray(byte[] a) {
      byte[] temp = a.clone();
      for (int count=0; count < temp.length; count++) {
          temp[count] = (byte)0xFF;
      }
      return temp;
  }

  @Test
  public void testGenericServerParams() throws InvalidInputException {
    // SERVER
    GenericServerSecretParams serverSecretParams = GenericServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    GenericServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // SERVER - deserialize test
    new GenericServerSecretParams(serverSecretParams.serialize());
    new GenericServerPublicParams(serverPublicParams.serialize());
    try {
      byte[] temp = new byte[32];  // wrong length
      new GenericServerSecretParams(temp);
      fail("Failed to catch invalid GenericServerSecretParams deserialize 1");
    } catch (InvalidInputException e) {
        // expected
    }
    try {
      new GenericServerSecretParams(makeBadArray(serverSecretParams.serialize()));
      fail("Failed to catch invalid GenericServerSecretParams deserialize 2");
    } catch (InvalidInputException e) {
        // expected
    }
    try {
        byte[] temp = new byte[32];  // wrong length
        new GenericServerPublicParams(temp);
        fail("Failed to catch invalid GenericServerPublicParams deserialize 1");
    } catch (InvalidInputException e) {
        // expected
    }
    try {
        new GenericServerPublicParams(makeBadArray(serverPublicParams.serialize()));
        fail("Failed to catch invalid GenericServerPublicParams deserialize 2");
    } catch (InvalidInputException e) {
        // expected
    }
  }

  @Test
  public void testCreateCallLinkIntegration() throws InvalidInputException, VerificationFailedException {
    // SERVER
    // Generate keys
    GenericServerSecretParams serverSecretParams = GenericServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    GenericServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // CLIENT
    // Generate keys
    CallLinkSecretParams clientSecretParams = CallLinkSecretParams.deriveFromRootKey(TEST_ARRAY_32_1);
    CallLinkPublicParams clientPublicParams = clientSecretParams.getPublicParams();

    // Create context and request
    byte[] roomId = TEST_ARRAY_32_2;
    CreateCallLinkCredentialRequestContext context = CreateCallLinkCredentialRequestContext.forRoom(roomId, createSecureRandom(TEST_ARRAY_32_3));
    CreateCallLinkCredentialRequest        request = context.getRequest();

    // SERVER
    // Issue credential
    Instant timestamp = Instant.now().truncatedTo(ChronoUnit.DAYS);
    CreateCallLinkCredentialResponse response = request.issueCredential(TEST_USER_ID, timestamp, serverSecretParams, createSecureRandom(TEST_ARRAY_32_4));

    // CLIENT
    // Gets stored credential
    CreateCallLinkCredential credential = context.receiveResponse(response, TEST_USER_ID, serverPublicParams);
    CreateCallLinkCredentialPresentation presentation = credential.present(roomId, TEST_USER_ID, serverPublicParams, clientSecretParams, createSecureRandom(TEST_ARRAY_32_5));

    // SERVER
    // Verify presentation
    presentation.verify(roomId, serverSecretParams, clientPublicParams);
    presentation.verify(roomId, timestamp.plus(1, ChronoUnit.DAYS), serverSecretParams, clientPublicParams);

    try {
        presentation.verify(roomId, timestamp.plus(30, ChronoUnit.HOURS), serverSecretParams, clientPublicParams);
        fail("credential expired 1");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        presentation.verify(roomId, timestamp.plus(30, ChronoUnit.HOURS).plusSeconds(1), serverSecretParams, clientPublicParams);
        fail("credential expired 2");
    } catch (VerificationFailedException e) {
        // expected
    }
  }

  @Test
  public void testCallLinkAuthIntegration() throws InvalidInputException, VerificationFailedException {
    // SERVER
    // Generate keys
    GenericServerSecretParams serverSecretParams = GenericServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    GenericServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // CLIENT
    // Generate keys
    CallLinkSecretParams clientSecretParams = CallLinkSecretParams.deriveFromRootKey(TEST_ARRAY_32_1);
    CallLinkPublicParams clientPublicParams = clientSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    Instant redemptionTime = Instant.now().truncatedTo(ChronoUnit.DAYS);
    CallLinkAuthCredentialResponse response = CallLinkAuthCredentialResponse.issueCredential(TEST_USER_ID, redemptionTime, serverSecretParams, createSecureRandom(TEST_ARRAY_32_4));

    // CLIENT
    // Gets stored credential
    CallLinkAuthCredential credential = response.receive(TEST_USER_ID, redemptionTime, serverPublicParams);
    CallLinkAuthCredentialPresentation presentation = credential.present(TEST_USER_ID, redemptionTime, serverPublicParams, clientSecretParams, createSecureRandom(TEST_ARRAY_32_5));

    // SERVER
    // Verify presentation
    presentation.verify(serverSecretParams, clientPublicParams);
    presentation.verify(redemptionTime.plus(1, ChronoUnit.DAYS), serverSecretParams, clientPublicParams);

    try {
        presentation.verify(redemptionTime.plus(3, ChronoUnit.DAYS), serverSecretParams, clientPublicParams);
        fail("credential expired 1");
    } catch (VerificationFailedException e) {
        // expected
    }

    // CLIENT
    assertEquals(TEST_USER_ID, clientSecretParams.decryptUserId(presentation.getUserId()));
  }
}


//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.integrationtests;

import java.io.UnsupportedEncodingException;
import org.junit.Test;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ServiceId.Pni;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.NotarySignature;
import org.signal.libsignal.zkgroup.SecureRandomTest;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.auth.AuthCredential;
import org.signal.libsignal.zkgroup.auth.AuthCredentialPresentation;
import org.signal.libsignal.zkgroup.auth.AuthCredentialResponse;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPni;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.ClientZkGroupCipher;
import org.signal.libsignal.zkgroup.groups.GroupMasterKey;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.zkgroup.groups.ProfileKeyCiphertext;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.profiles.ClientZkProfileOperations;
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredential;
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredentialResponse;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCommitment;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialPresentation;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequest;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequestContext;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public final class ZkGroupTest extends SecureRandomTest {

  private static final UUID   TEST_UUID       = UUID.fromString("00010203-0405-0607-0809-0a0b0c0d0e0f");

  private static final UUID   TEST_UUID_1     = UUID.fromString("64656667-6869-6A6B-6C6D-6E6F70717273");

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

  private static final byte[] authPresentationResultV2 = Hex.      fromStringCondensedAssert("01322f9100de0734550a81dc81724a81dbd3b1b43dbc1d552d53455911c2772f34a6356ca17c6d34d858391456af55d0ef841fbe1fa8c4ee810f21e0bb9f4ace4c5c48c72ebbeb2ccda5f7aa49aee6bc0051cdde166e0f8c5f1febd53a4437c570ee1aa223f5eb937db98f34e3653d85ec163f39847222a2dec4235ea41c47bb62028aae30945857ee77663079bcc4923d14a43ad4f6bc33715046f7bde52715375ca9f89be0e630d4bdaa211156d0306723f543b06f5e998447b962c8e9729b4cc00000000000000074d0eae8e4311a6ae3d2970ef198c398110462be47dd2f26e6559209ef6cc20001a05a0b319a172dbeb2293cc1e0e191cefb23e24cf0d6b4b5373a30044be10cb033674d631e17dfce09398f234e9d62e118a6077caea0ef8bf67d7d723db70fecf2098fa041317b7be9fdbb68b0f25f5c479d68bd917fc6f187c5bf7a58910231921fc43565232466325c039212362b6d1203ccaedf831dc7f9060dcaaffa02624042171f5f0e780b9f74cfa88a147f3f1c082f9ca8638af1788e7899cbae0c765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547440e20100");

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
  public void testAuthIntegration() throws VerificationFailedException, InvalidInputException {

    Aci aci            = new Aci(TEST_UUID);
    int redemptionTime = 123456;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    // SERVER - deserialize test
    {
        new ServerSecretParams(serverSecretParams.serialize());
        new ServerPublicParams(serverPublicParams.serialize());
        try {
            byte[] temp = new byte[32];  // wrong length
            new ServerSecretParams(temp);
            throw new AssertionError("Failed to catch invalid ServerSecretParams deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new ServerSecretParams(makeBadArray(serverSecretParams.serialize()));
            throw new AssertionError("Failed to catch invalid ServerSecretParams deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            byte[] temp = new byte[32];  // wrong length
            new ServerPublicParams(temp);
            throw new AssertionError("Failed to catch invalid ServerPublicParams deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new ServerPublicParams(makeBadArray(serverPublicParams.serialize()));
            throw new AssertionError("Failed to catch invalid ServerPublicParams deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }

    ServerZkAuthOperations serverZkAuth       = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();

    // CLIENT - deserialize test
    {
        new GroupSecretParams(groupSecretParams.serialize());
        new GroupPublicParams(groupPublicParams.serialize());
        try {
            byte[] temp = new byte[10];  // wrong length
            new GroupMasterKey(temp);
            throw new AssertionError("Failed to catch invalid GroupMasterKey deserialize");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            byte[] temp = new byte[10];  // wrong length
            new GroupSecretParams(temp);
            throw new AssertionError("Failed to catch invalid GroupSecretParams deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new GroupSecretParams(makeBadArray(groupSecretParams.serialize()));
            throw new AssertionError("Failed to catch invalid GroupSecretParams deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            byte[] temp = new byte[10];  // wrong length
            new GroupPublicParams(temp);
            throw new AssertionError("Failed to catch invalid GroupPublicParams deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new GroupPublicParams(makeBadArray(groupPublicParams.serialize()));
            throw new AssertionError("Failed to catch invalid GroupPublicParams deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }

    // SERVER
    // Issue credential
    AuthCredentialResponse authCredentialResponse = serverZkAuth.issueAuthCredential(createSecureRandom(TEST_ARRAY_32_2), aci, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredential         authCredential      = clientZkAuthCipher.receiveAuthCredential(aci, redemptionTime, authCredentialResponse);

    // CLIENT - deserialize test
    {
        new AuthCredentialResponse(authCredentialResponse.serialize());
        try {
            byte[] temp = new byte[10];
            new AuthCredentialResponse(temp);
            throw new AssertionError("Failed to catch invalid AuthCredentialResponse deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new AuthCredentialResponse(makeBadArray(authCredentialResponse.serialize()));
            throw new AssertionError("Failed to catch invalid AuthCredentialResponse deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }

    // CLIENT - verify test
    {
        UUID badUuid = TEST_UUID_1;
        try {
            clientZkAuthCipher.receiveAuthCredential(new Aci(badUuid), redemptionTime, authCredentialResponse);
            throw new AssertionError("Failed to catch invalid AuthCredential 1");
        } catch (VerificationFailedException e) {
            // expected
        }

        byte[] temp = authCredentialResponse.serialize();
        temp[1]++;
        AuthCredentialResponse badResponse = new AuthCredentialResponse(temp);  
        try {
            clientZkAuthCipher.receiveAuthCredential(aci, redemptionTime, badResponse);
            throw new AssertionError("Failed to catch invalid AuthCredential 2");
        } catch (VerificationFailedException e) {
            // expected
        }
    }

    // Create and decrypt user entry
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encrypt(aci);
    ServiceId      plaintext      = clientZkGroupCipher.decrypt(uuidCiphertext);
    assertEquals(aci, plaintext);

    // CLIENT - deserialize test
    {
        new UuidCiphertext(uuidCiphertext.serialize());
        try {
            byte[] temp = new byte[10];
            new UuidCiphertext(temp);
            throw new AssertionError("Failed to catch invalid UuidCiphertext deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }

        try {
            new UuidCiphertext(makeBadArray(uuidCiphertext.serialize()));
            throw new AssertionError("Failed to catch invalid UuidCiphertext deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }

    // CLIENT - verify test
    {
        byte[] temp = uuidCiphertext.serialize();
        temp[3]++; // We need a bad ciphertext that passes deserialization, this seems to work
        try {
            clientZkGroupCipher.decrypt(new UuidCiphertext(temp));
            throw new AssertionError("Failed to catch invalid UuidCiphertext decrypt");
        } catch (VerificationFailedException e) {
            // expected
        }
    }

    // CLIENT - Create presentation
    AuthCredentialPresentation presentation = clientZkAuthCipher.createAuthCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, authCredential);
    assertEquals(presentation.serialize()[0], 1); // Check V2 (versions start from 1 but are encoded starting from 0)
    assertEquals(presentation.getVersion(), AuthCredentialPresentation.Version.V2);
    assertArrayEquals(presentation.serialize(), authPresentationResultV2);

    // CLIENT - deserialize test
    {
        new AuthCredentialPresentation(presentation.serialize());
        byte[] temp = new byte[10];
        try {
            new AuthCredentialPresentation(temp);
            throw new AssertionError("Failed to catch invalid AuthCredentialPresentation deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new AuthCredentialPresentation(makeBadArray(presentation.serialize()));
            throw new AssertionError("Failed to catch invalid AuthCredentialPresentation deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }

    // SERVER - Verify presentation, using times at the edge of the acceptable window
    Instant redemptionInstant = Instant.ofEpochSecond(86400L * redemptionTime);
    UuidCiphertext uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());
    assertNull(presentation.getPniCiphertext());
    assertEquals(presentation.getRedemptionTime(), redemptionInstant);

    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionInstant.minus(1, ChronoUnit.DAYS));
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionInstant.plus(2, ChronoUnit.DAYS));

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionInstant.minus(1, ChronoUnit.DAYS).minus(1, ChronoUnit.SECONDS));
        throw new AssertionError("verifyAuthCredentialPresentation should fail #1!");
    } catch (VerificationFailedException e) {
      // good
    }

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionInstant.plus(2, ChronoUnit.DAYS).plus(1, ChronoUnit.SECONDS));
        throw new AssertionError("verifyAuthCredentialPresentation should fail #2!");
    } catch (VerificationFailedException e) {
      // good
    }

    try {
        byte[] temp = presentation.serialize();
        temp[3]++;  // We need a bad presentation that passes deserialization, this seems to work
        AuthCredentialPresentation presentationTemp = new AuthCredentialPresentation(temp);
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentationTemp, redemptionInstant);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #3!");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 0; // This interprets a V2 as V1, so should fail
        AuthCredentialPresentation presentationTemp = new AuthCredentialPresentation(temp);
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentationTemp, redemptionInstant);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #4");
    } catch (InvalidInputException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 40; // This interprets a V2 as a non-existent version, so should fail
        AuthCredentialPresentation presentationTemp = new AuthCredentialPresentation(temp);
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentationTemp, redemptionInstant);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #5");
    } catch (InvalidInputException e) {
        // expected
    }

  }


  @Test
  public void testAuthIntegrationCurrentTime() throws VerificationFailedException, InvalidInputException {

    // This test is mostly the same as testAuthIntegration() except instead of using a hardcoded
    // redemption date to compare against test vectors, it uses the current time

    Aci aci            = new Aci(TEST_UUID);
    int redemptionTime = (int)(Instant.now().truncatedTo(ChronoUnit.DAYS).getEpochSecond() / 86400);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();
    ServerZkAuthOperations serverZkAuth       = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    AuthCredentialResponse authCredentialResponse = serverZkAuth.issueAuthCredential(createSecureRandom(TEST_ARRAY_32_2), aci, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredential         authCredential      = clientZkAuthCipher.receiveAuthCredential(aci, redemptionTime, authCredentialResponse);

    // Create and decrypt user entry
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encrypt(aci);
    ServiceId      plaintext      = clientZkGroupCipher.decrypt(uuidCiphertext);
    assertEquals(aci, plaintext);

    // Create presentation
    AuthCredentialPresentation presentation = clientZkAuthCipher.createAuthCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, authCredential);

    // Verify presentation, using times at the edge of the acceptable window
    Instant redemptionInstant = Instant.ofEpochSecond(86400L * redemptionTime);
    UuidCiphertext uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());
    assertEquals(presentation.getRedemptionTime(), redemptionInstant);

    // By default the library uses the current time
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation);

    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionInstant.minus(1, ChronoUnit.DAYS));
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionInstant.plus(2, ChronoUnit.DAYS));

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionInstant.minus(1, ChronoUnit.DAYS).minus(1, ChronoUnit.SECONDS));
        throw new AssertionError("verifyAuthCredentialPresentation should fail #1!");
    } catch (VerificationFailedException e) {
      // good
    }

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionInstant.plus(2, ChronoUnit.DAYS).plus(1, ChronoUnit.SECONDS));
        throw new AssertionError("verifyAuthCredentialPresentation should fail #2!");
    } catch (VerificationFailedException e) {
      // good
    }
  }

  @Test
  public void testAuthWithPniIntegration() throws VerificationFailedException, InvalidInputException {

    Aci     aci            = new Aci(TEST_UUID);
    Pni     pni            = new Pni(TEST_UUID_1);
    Instant redemptionTime = Instant.now().truncatedTo(ChronoUnit.DAYS);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    ServerZkAuthOperations serverZkAuth   = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    AuthCredentialWithPniResponse authCredentialResponse = serverZkAuth.issueAuthCredentialWithPniAsServiceId(createSecureRandom(TEST_ARRAY_32_2), aci, pni, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredentialWithPni  authCredential      = clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(aci, pni, redemptionTime.getEpochSecond(), authCredentialResponse);

    // CLIENT - deserialize test
    {
        new AuthCredentialWithPniResponse(authCredentialResponse.serialize());
        try {
            byte[] temp = new byte[10];
            new AuthCredentialWithPniResponse(temp);
            throw new AssertionError("Failed to catch invalid AuthCredentialWithPniResponse deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new AuthCredentialWithPniResponse(makeBadArray(authCredentialResponse.serialize()));
            throw new AssertionError("Failed to catch invalid AuthCredentialWithPniResponse deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }
    
    // CLIENT - verify test
    {
        try {
            // Switch ACI and PNI
            clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(new Aci(pni.getRawUUID()), new Pni(aci.getRawUUID()), redemptionTime.getEpochSecond(), authCredentialResponse);
            throw new AssertionError("Failed to catch invalid AuthCredentialWithPni 1");
        } catch (VerificationFailedException e) {
            // expected
        }

        byte[] temp = authCredentialResponse.serialize();
        temp[1]++;
        AuthCredentialWithPniResponse badResponse = new AuthCredentialWithPniResponse(temp);  
        try {
            clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(aci, pni, redemptionTime.getEpochSecond(), badResponse);
            throw new AssertionError("Failed to catch invalid AuthCredentialWithPni 2");
        } catch (VerificationFailedException e) {
            // expected
        }

        try {
            // Use wrong kind of AuthCredentialWithPni
            clientZkAuthCipher.receiveAuthCredentialWithPniAsAci(aci, pni, redemptionTime.getEpochSecond(), authCredentialResponse);
            throw new AssertionError("Failed to catch AuthCredentialWithServiceId treated as Aci");
        } catch (VerificationFailedException e) {
            // expected
        }
    }

    // Create and decrypt user entry
    UuidCiphertext aciCiphertext = clientZkGroupCipher.encrypt(aci);
    ServiceId      aciPlaintext  = clientZkGroupCipher.decrypt(aciCiphertext);
    assertEquals(aci, aciPlaintext);
    UuidCiphertext pniCiphertext = clientZkGroupCipher.encrypt(pni);
    ServiceId      pniPlaintext  = clientZkGroupCipher.decrypt(pniCiphertext);
    assertEquals(pni, pniPlaintext);

    // CLIENT - Create presentation
    AuthCredentialPresentation presentation = clientZkAuthCipher.createAuthCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, authCredential);
    assertEquals(presentation.serialize()[0], 2); // Check V3 (versions start from 1 but are encoded starting from 0)
    assertEquals(presentation.getVersion(), AuthCredentialPresentation.Version.V3);

    // CLIENT - deserialize test
    {
        new AuthCredentialPresentation(presentation.serialize());
        byte[] temp = new byte[10];
        try {
            new AuthCredentialPresentation(temp);
            throw new AssertionError("Failed to catch invalid AuthCredentialPresentation deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new AuthCredentialPresentation(makeBadArray(presentation.serialize()));
            throw new AssertionError("Failed to catch invalid AuthCredentialPresentation deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }

    // SERVER - Verify presentation, using times at the edge of the acceptable window
    assertArrayEquals(aciCiphertext.serialize(), presentation.getUuidCiphertext().serialize());
    assertArrayEquals(pniCiphertext.serialize(), presentation.getPniCiphertext().serialize());
    assertEquals(presentation.getRedemptionTime(), redemptionTime);

    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionTime.minus(1, ChronoUnit.DAYS));
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionTime.plus(2, ChronoUnit.DAYS));

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionTime.minus(1, ChronoUnit.DAYS).minus(1, ChronoUnit.SECONDS));
        throw new AssertionError("verifyAuthCredentialPresentation should fail #1!");
    } catch (VerificationFailedException e) {
      // good
    }

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionTime.plus(2, ChronoUnit.DAYS).plus(1, ChronoUnit.SECONDS));
        throw new AssertionError("verifyAuthCredentialPresentation should fail #2!");
    } catch (VerificationFailedException e) {
      // good
    }

    try {
        byte[] temp = presentation.serialize();
        temp[3] += 5;  // We need a bad presentation that passes deserialization, this seems to work
        AuthCredentialPresentation presentationTemp = new AuthCredentialPresentation(temp);
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentationTemp, redemptionTime);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #3!");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 0; // This interprets a V3 as V1, so should fail
        AuthCredentialPresentation presentationTemp = new AuthCredentialPresentation(temp);
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentationTemp, redemptionTime);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #4");
    } catch (InvalidInputException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 40; // This interprets a V3 as a non-existent version, so should fail
        AuthCredentialPresentation presentationTemp = new AuthCredentialPresentation(temp);
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentationTemp, redemptionTime);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #5");
    } catch (InvalidInputException e) {
        // expected
    }

  }

  @Test
  public void testAuthWithPniAsAciIntegration() throws VerificationFailedException, InvalidInputException {

    Aci     aci            = new Aci(TEST_UUID);
    Pni     pni            = new Pni(TEST_UUID_1);
    Instant redemptionTime = Instant.now().truncatedTo(ChronoUnit.DAYS);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    ServerZkAuthOperations serverZkAuth   = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    AuthCredentialWithPniResponse authCredentialResponse = serverZkAuth.issueAuthCredentialWithPniAsAci(createSecureRandom(TEST_ARRAY_32_2), aci, pni, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredentialWithPni  authCredential      = clientZkAuthCipher.receiveAuthCredentialWithPniAsAci(aci, pni, redemptionTime.getEpochSecond(), authCredentialResponse);

    // CLIENT - verify test
    {
        try {
            // Use wrong kind of AuthCredentialWithPni
            clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(aci, pni, redemptionTime.getEpochSecond(), authCredentialResponse);
            throw new AssertionError("Failed to catch AuthCredentialWithPniAsAci treated as ServiceId");
        } catch (VerificationFailedException e) {
            // expected
        }
    }

    // Create and decrypt user entry
    UuidCiphertext aciCiphertext = clientZkGroupCipher.encrypt(aci);
    ServiceId      aciPlaintext  = clientZkGroupCipher.decrypt(aciCiphertext);
    assertEquals(aci, aciPlaintext);
    Aci            pniAsAci      = new Aci(pni.getRawUUID());
    UuidCiphertext pniCiphertext = clientZkGroupCipher.encrypt(pniAsAci);
    ServiceId      pniPlaintext  = clientZkGroupCipher.decrypt(pniCiphertext);
    assertEquals(pniAsAci, pniPlaintext);

    // CLIENT - Create presentation
    AuthCredentialPresentation presentation = clientZkAuthCipher.createAuthCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, authCredential);
    assertEquals(presentation.serialize()[0], 2); // Check V3 (versions start from 1 but are encoded starting from 0)
    assertEquals(presentation.getVersion(), AuthCredentialPresentation.Version.V3);

    // SERVER - Verify presentation, using times at the edge of the acceptable window
    assertArrayEquals(aciCiphertext.serialize(), presentation.getUuidCiphertext().serialize());
    assertArrayEquals(pniCiphertext.serialize(), presentation.getPniCiphertext().serialize());
    assertEquals(presentation.getRedemptionTime(), redemptionTime);

    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionTime.minus(1, ChronoUnit.DAYS));
    serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionTime.plus(2, ChronoUnit.DAYS));

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionTime.minus(1, ChronoUnit.DAYS).minus(1, ChronoUnit.SECONDS));
        throw new AssertionError("verifyAuthCredentialPresentation should fail #1!");
    } catch (VerificationFailedException e) {
      // good
    }

    try {
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentation, redemptionTime.plus(2, ChronoUnit.DAYS).plus(1, ChronoUnit.SECONDS));
        throw new AssertionError("verifyAuthCredentialPresentation should fail #2!");
    } catch (VerificationFailedException e) {
      // good
    }

    try {
        byte[] temp = presentation.serialize();
        temp[3] += 5;  // We need a bad presentation that passes deserialization, this seems to work
        AuthCredentialPresentation presentationTemp = new AuthCredentialPresentation(temp);
        serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams, presentationTemp, redemptionTime);
        throw new AssertionError("verifyAuthCredentialPresentation should fail #3!");
    } catch (VerificationFailedException e) {
        // expected
    }
  }

  @Test
  public void testExpiringProfileKeyIntegration() throws VerificationFailedException, InvalidInputException, UnsupportedEncodingException {

    Aci userId           = new Aci(TEST_UUID);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();
    ServerZkProfileOperations serverZkProfile    = new ServerZkProfileOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams     groupPublicParams     = groupSecretParams.getPublicParams();
    ClientZkProfileOperations clientZkProfileCipher = new ClientZkProfileOperations(serverPublicParams);

    ProfileKey           profileKey             = new ProfileKey(TEST_ARRAY_32_1);
    ProfileKeyCommitment profileKeyCommitment = profileKey.getCommitment(userId);

    // Create context and request
    ProfileKeyCredentialRequestContext context = clientZkProfileCipher.createProfileKeyCredentialRequestContext(createSecureRandom(TEST_ARRAY_32_3), userId, profileKey);
    ProfileKeyCredentialRequest        request = context.getRequest();

    // SERVER 
    Instant expiration = Instant.now().truncatedTo(ChronoUnit.DAYS).plus(5, ChronoUnit.DAYS);
    ExpiringProfileKeyCredentialResponse response = serverZkProfile.issueExpiringProfileKeyCredential(createSecureRandom(TEST_ARRAY_32_4), request, userId, profileKeyCommitment, expiration);

    // SERVER - verification test
    {
        byte[] temp = request.serialize();
        temp[4]++;  // We need a bad presentation that passes deserialization, this seems to work
        ProfileKeyCredentialRequest badRequest = new ProfileKeyCredentialRequest(temp);
        try {
            serverZkProfile.issueExpiringProfileKeyCredential(createSecureRandom(TEST_ARRAY_32_4), badRequest, userId, profileKeyCommitment, expiration);
            throw new AssertionError("Failed to catch invalid ProfileKeyCredentialRequest");
        } catch (VerificationFailedException e) {
            // expected
        }
    }
   
    // CLIENT
    // Gets stored profile credential
    ClientZkGroupCipher          clientZkGroupCipher  = new ClientZkGroupCipher(groupSecretParams);
    ExpiringProfileKeyCredential profileKeyCredential = clientZkProfileCipher.receiveExpiringProfileKeyCredential(context, response);

    // Create encrypted UID and profile key
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encrypt(userId);
    ServiceId      plaintext      = clientZkGroupCipher.decrypt(uuidCiphertext);
    assertEquals(plaintext, userId);

    ProfileKeyCiphertext profileKeyCiphertext   = clientZkGroupCipher.encryptProfileKey(profileKey, userId);
    ProfileKey           decryptedProfileKey    = clientZkGroupCipher.decryptProfileKey(profileKeyCiphertext, userId);
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());

    assertEquals(expiration, profileKeyCredential.getExpirationTime());

    ProfileKeyCredentialPresentation presentation = clientZkProfileCipher.createProfileKeyCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, profileKeyCredential);
    assertEquals(presentation.serialize()[0], 2); // Check V3 (versions start from 1 but are encoded starting from 0)
    assertEquals(presentation.getVersion(), ProfileKeyCredentialPresentation.Version.V3);

    // Verify presentation
    serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentation);
    serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentation, expiration.minusSeconds(5));
    UuidCiphertext uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());

    try {
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentation, expiration);
        throw new AssertionError("credential expired 1");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentation, expiration.plusSeconds(5));
        throw new AssertionError("credential expired 2");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[2] += 8;  // We need a bad presentation that passes deserializaton, this seems to work
        ProfileKeyCredentialPresentation presentationTemp = new ProfileKeyCredentialPresentation(temp);
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyProfileKeyCredentialPresentation should fail 1");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 0; // This interprets a V3 as V1, so should fail
        ProfileKeyCredentialPresentation presentationTemp = new ProfileKeyCredentialPresentation(temp);
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyProfileKeyCredentialPresentation should fail 2");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 40; // This interprets a V3 as a non-existent version, so should fail
        ProfileKeyCredentialPresentation presentationTemp = new ProfileKeyCredentialPresentation(temp);
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyProfileKeyCredentialPresentation should fail 3");
    } catch (InvalidInputException e) {
        // expected
    }

    // Test that we can encode as a V1 presentation, even though it won't verify.
    ProfileKeyCredentialPresentation v1Presentation = new ProfileKeyCredentialPresentation(presentation.getStructurallyValidV1PresentationBytes());
    assertEquals(v1Presentation.getUuidCiphertext(), presentation.getUuidCiphertext());
    assertEquals(v1Presentation.getProfileKeyCiphertext(), presentation.getProfileKeyCiphertext());
    try {
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, v1Presentation);
    } catch (VerificationFailedException e) {
        // expected
    }
  }

  @Test
  public void testServerSignatures() throws VerificationFailedException {
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();

    byte[] message = TEST_ARRAY_32_1;

    NotarySignature signature = serverSecretParams.sign(createSecureRandom(TEST_ARRAY_32_2), message);
    serverPublicParams.verifySignature(message, signature);

    assertByteArray(
"87d354564d35ef91edba851e0815612e864c227a0471d50c270698604406d003a55473f576cf241fc6b41c6b16e5e63b333c02fe4a33858022fdd7a4ab367b06", signature.serialize());

    byte[] alteredMessage = message.clone();
    alteredMessage[0] ^= 1;
    try {
        serverPublicParams.verifySignature(alteredMessage, signature);
        throw new AssertionError("signature validation should have failed!");
    } catch (VerificationFailedException e) {
      // good
    }
  }

  @Test
  public void testGroupIdentifier() throws VerificationFailedException {
    GroupSecretParams   groupSecretParams   = GroupSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    //assertByteArray("31f2c60f86f4c5996e9e2568355591d9", groupPublicParams.getGroupIdentifier().serialize());
  }

  @Test(expected = InvalidInputException.class)
  public void testInvalidSerialized() throws InvalidInputException {

    byte[] ckp = new byte[97]; // right size, wrong contents
    Arrays.fill(ckp, (byte) -127);

    GroupPublicParams groupSecretParams = new GroupPublicParams(ckp);
  }

  @Test(expected = InvalidInputException.class)
  public void testInvalidSerializedInfallible() throws InvalidInputException {

    byte[] ckp = new byte[289]; // right size, wrong contents
    Arrays.fill(ckp, (byte) -127);

    GroupSecretParams groupSecretParams = new GroupSecretParams(ckp);
  }

  @Test(expected = InvalidInputException.class)
  public void testWrongSizeSerialized() throws InvalidInputException {

    byte[] ckp = new byte[5]; // right size, wrong contents
    Arrays.fill(ckp, (byte) -127);

    GroupPublicParams groupSecretParams = new GroupPublicParams(ckp);
  }

  @Test(expected = InvalidInputException.class)
  public void testWrongSizeSerializedInfallible() throws InvalidInputException {

    byte[] ckp = new byte[5]; // right size, wrong contents
    Arrays.fill(ckp, (byte) -127);

    GroupSecretParams groupSecretParams = new GroupSecretParams(ckp);
  }

  @Test
  public void testBlobEncryption() throws InvalidInputException, VerificationFailedException {

    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);
    ClientZkGroupCipher clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    byte[] plaintext = Hex.fromStringCondensedAssert("0102030405060708111213141516171819");
    byte[] ciphertext = Hex.fromStringCondensedAssert("dd4d032ca9bb75a4a78541b90cb4e95743f3b0dabfc7e11101b098e34f6cf6513940a04c1f20a302692afdc7087f10196000");

    byte[] ciphertextPaddedWith257 = Hex.fromStringCondensedAssert("5cb5b7bff06e85d929f3511fd194e638cf32a47663868bc8e64d98fb1bbe435ebd21c763ce2d42e85a1b2c169f12f9818ddadcf4b491398b7c5d46a224e1582749f5e2a4a2294caaaaab843a1b7cf6426fd543d09ff32a4ba5f319ca4442b4da34b3e2b5b4f8a52fdc4b484ea86b33db3ebb758dbd9614178f0e4e1f9b2b914f1e786936b62ed2b58b7ae3cb3e7ae0835b9516959837406662b85eac740cef83b60b5aaeaaab95643c2bef8ce87358fabff9d690052beb9e52d0c947e7c986b2f3ce3b7161cec72c08e2c4ade3debe3792d736c0457bc352afb8b6caa48a5b92c1ec05ba808ba8f94c6572ebbf29818912344987573de419dbcc7f1ea0e4b2dd4077b76b381819747ac332e46fa23abfc3338e2f4b081a8a53cba0988eef116764d944f1ce3f20a302692afdc7087f10196000");

    byte[] ciphertext2 = clientZkGroupCipher.encryptBlob(createSecureRandom(TEST_ARRAY_32_2), plaintext);
    byte[] plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext2);

    assertArrayEquals(plaintext, plaintext2);
    assertArrayEquals(ciphertext, ciphertext2);

    byte[] plaintext257 = clientZkGroupCipher.decryptBlob(ciphertextPaddedWith257);
    assertArrayEquals(plaintext, plaintext257);
  }

  @Test
  public void testDeriveAccessKey() throws Exception {
    byte[] expectedAccessKey = Hex.fromStringCondensedAssert("5a723acee52c5ea02b92a3a360c09595");
    byte[] profileKey = new byte[32];
    Arrays.fill(profileKey, (byte)0x02);

    byte[] result = new ProfileKey(profileKey).deriveAccessKey();
    assertArrayEquals(result, expectedAccessKey);
  }

  private void assertByteArray(String expectedAsHex, byte[] actual) {
    byte[] expectedBytes = Hex.fromStringCondensedAssert(expectedAsHex);

    assertArrayEquals(expectedBytes, actual);
  }

}


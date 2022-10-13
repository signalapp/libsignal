//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.integrationtests;

import java.io.UnsupportedEncodingException;
import org.junit.Test;
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
import org.signal.libsignal.zkgroup.profiles.PniCredential;
import org.signal.libsignal.zkgroup.profiles.PniCredentialPresentation;
import org.signal.libsignal.zkgroup.profiles.PniCredentialRequestContext;
import org.signal.libsignal.zkgroup.profiles.PniCredentialResponse;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCommitment;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredential;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialPresentation;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequest;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequestContext;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialResponse;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyVersion;
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

private static final byte[] profileKeyPresentationResultV1 = Hex.fromStringCondensedAssert(
"00c4d19bca1ae844585168869da4133e0e0bb59f2ce17b7ac65bff5da9610eca103429d8022a94bae2b5b1057b5595b8ad70bfc2d0e1ad662cb75e6bae0782be6f00e3db793bc28561f0196c2e74da6f303fa8bcb70c94096671b73f7b3a95fb002200d5b9180fa0ef7d3014d01344145b4d38480d72ff25c24294e305e5705072e0d32cc4e84f5caf31486089a4b934c80c92eba43472ff23a5af93c397535d33801f0e6fc6eb2ee0d117f03bb4fd38a8b9c88d94708131f38742ca804a3cfc4f9476bc2d03f53d17001c36478afbe9cc535a224b2df6b2b08bef06cbc7d4dc42ccfc3459f7ac5c4419ae9f3c8a161d554d047778943216240858da3b1101984c40010000000000007a01eea6b2adad14d71ab8b8e411bef3c596e954b70e4031570cb1abd7e932083241f1caca3116708fa4319fbbdfe351376c23644ae09a42f0155db4996c9d0c7ffc8521c1914c0e1a20ae51e65df64dd5e6e5985b3d9d31732046d2d77f9c08aaccf056b84026073976eec6164cbdaee5d9e76e497f0c290af681cabd5c5101282abb26c3680d6087ce053310fe8a94f59d8ae23caac5fc0ed0c379888abf028a6f29f89d4fe2acc1706341b2245ba1885bca57e1e27ccf7ed79371500965009f960c2ba00fad3e93383b87ce119cac0b3360eb99284ce78e2cbed680f7960373e0ab75c190254160c2353614109489e653c9b2e1c93f92c7c5ad583d987a04bd3541b24485c33ea49bac43c87c4ab3efde2e2d7ec10a40be544199f925b20b2c55542bc56410571e41cd8e0286f609a66768b5061ccb4777af32309928dd09765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547448c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746");


  private static final byte[] authPresentationResultV2 = Hex.      fromStringCondensedAssert("01322f9100de0734550a81dc81724a81dbd3b1b43dbc1d552d53455911c2772f34a6356ca17c6d34d858391456af55d0ef841fbe1fa8c4ee810f21e0bb9f4ace4c5c48c72ebbeb2ccda5f7aa49aee6bc0051cdde166e0f8c5f1febd53a4437c570ee1aa223f5eb937db98f34e3653d85ec163f39847222a2dec4235ea41c47bb62028aae30945857ee77663079bcc4923d14a43ad4f6bc33715046f7bde52715375ca9f89be0e630d4bdaa211156d0306723f543b06f5e998447b962c8e9729b4cc00000000000000074d0eae8e4311a6ae3d2970ef198c398110462be47dd2f26e6559209ef6cc20001a05a0b319a172dbeb2293cc1e0e191cefb23e24cf0d6b4b5373a30044be10cb033674d631e17dfce09398f234e9d62e118a6077caea0ef8bf67d7d723db70fecf2098fa041317b7be9fdbb68b0f25f5c479d68bd917fc6f187c5bf7a58910231921fc43565232466325c039212362b6d1203ccaedf831dc7f9060dcaaffa02624042171f5f0e780b9f74cfa88a147f3f1c082f9ca8638af1788e7899cbae0c765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547440e20100");



private static final byte[] profileKeyPresentationResultV2 = Hex.fromStringCondensedAssert(
"01e0f49cef4f25c31d1bfdc4a328fd508d2222b6decee2a253cf71e8821e97cc3f86824f79b1884b43c67f854717b1a47f56c8ff50a1c07fddbf4f6e857027d548583b54079dd61d54cdd39cd4acae5f8b3bbfa2bb6b3502b69b36da77addddc145ef254a16f2baec1e3d7e8dc80730bc608fcd0e4d8cfef3330a496380c7ac648686b9c5b914d0a77ee84848aa970b2404450179b4022eef003387f6bdbcba30344cadfd5e3f1677caa2c785f4fefe042a1b2adf4f4b8fa6023e41d704bda901d3a697904770ac46e0e304cf19f91ce9ab0ed1ccad8a6febd72313455f139b9222e9a30a2265c6cd22ee5b907fc95967417a0d8ca338a5ee4d51bba78039c314e4001000000000000749d54772b8137e570157c068a5cfebb464b6c1133c72d9abfda72db421cd00561ac4eecb94313c6912013e32c322ea36743b01814fe919ca84b9aea9c78b10ba021506f7ad8c6625e87e07ce32b559036af6b67e2c0383a643cb93cdc2b9800e90588a18fcc449cd466c28c6db73507d8282dd00808b5927fee3336ed0a2202dfb1e176fece6a4104caa2a866c475209967638ea2f1466847da7301a77b9007dfb332a30e9bbfae8a8398165ec9dd4778214e0d6ed35a34071bdf3b3b19510ff2a617bc53eb0e6b0ddc501db027bb47e4f4127d7a0104945f3d3dc7ec1741038b9b80e2c7f131c519ee26ffcb7cb9d3556cd35a12bef1d4b376fc513197ba00ce8f012a0b374164222ba79a39e74e150813474ca6f87ba705c0f06e7b7068039c5edd9dd1a5ab6793ac211989907686b45650221187d4d59ae492679f3b4308765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547448c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746");

private static final byte[] pniPresentationResultV2 = Hex.fromStringCondensedAssert(
"01f887f403db1a80fa04043413233f56bf6c53bb078c16d24df93a219d7785696856d8f197a01c6e223d4aceed1d60b90b713f4556ab39403b84c51d724ca9aa44886d73be15fcebc933f835fc0f3210f8d7b8fa7940bf9069d50dc4ba83da8a0ed86d6c33cd99a25fe46906d655a7fec5fee500527a56ea5689d1765396907b153a86e40eb27b8120661dfe59bb17af1024ebd697c2c36c46f3a85f8dc6f92761b29c84256847b5f420386ac41d6d81f8e65a195f2ab7003c0fc22fd969870e2c5c4ad4a9de38a8bde73509c41e85accef59db69930972b1c3fcb9c9abd4c884a3e91b4c25b8fde3b5cac7c55442f996b3fd3712110c7dd71c847be552122b947402136b1c16fe18acba2e6a277dc57172ac79d189246060d50db1a7dc531d075ec9414f86e31a1b0406ce173b09c1eabbef2de117749b3c512499d5f91e4694e4001000000000000769c0c6c310ed2b8f4a1d1e6b853d83f5da8136e36605fd631979cc618d0e102cc82e9056d2031379de3e57c04530b20617d0b2418b8950c8a2394355c6d400f0e4f69b75942032067382ae244870f5859a35782cb81b1106c5aae58df1f110dbf761c3a52ad5e3a872f385c3056bf2be3d67826cf33bc743c1c25eed0eda20f21de773906657b26e09cf388da2333db60f768865e2405f4df4f48b640295e027625678a810dbf8111918f7b127fd9fb0b332531ec52069b98abf95bb4ae7307d96b9d50b6e734ff8af92d2c8417919795a46b97df7a692df4ea9b63810ef70dca68693bbec7e1f52409430da61cac9249ca02216a77b1f08e5951a50783ca088fa5992b5ecaf1413dfe45f9ef23b3c120994118b325763d66e60c9647cc380248a9da79e46c17b6bb03a23c3987cea86ac158d45b78f1f9b923472521ecb30e765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f525474fe74409060615679fc115473683d63abd9ced46c7f2ad736046de5a2c7d2522f122895597049cfd7cc5beb6dc72aa990ae9a62ec8e256a1cbf5f3f284233bb0748c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746");

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

    UUID uuid           = TEST_UUID;
    int  redemptionTime = 123456;

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
    AuthCredentialResponse authCredentialResponse = serverZkAuth.issueAuthCredential(createSecureRandom(TEST_ARRAY_32_2), uuid, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredential         authCredential      = clientZkAuthCipher.receiveAuthCredential(uuid, redemptionTime, authCredentialResponse);

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
            clientZkAuthCipher.receiveAuthCredential(badUuid, redemptionTime, authCredentialResponse);
            throw new AssertionError("Failed to catch invalid AuthCredential 1");
        } catch (VerificationFailedException e) {
            // expected
        }

        byte[] temp = authCredentialResponse.serialize();
        temp[1]++;
        AuthCredentialResponse badResponse = new AuthCredentialResponse(temp);  
        try {
            clientZkAuthCipher.receiveAuthCredential(uuid, redemptionTime, badResponse);
            throw new AssertionError("Failed to catch invalid AuthCredential 2");
        } catch (VerificationFailedException e) {
            // expected
        }
    }

    // Create and decrypt user entry
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    UUID           plaintext      = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assertEquals(uuid, plaintext);

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
            clientZkGroupCipher.decryptUuid(new UuidCiphertext(temp));
            throw new AssertionError("Failed to catch invalid UuidCiphertext decrypt");
        } catch (VerificationFailedException e) {
            // expected
        }
    }

    // CLIENT - Create presentation
    AuthCredentialPresentation presentation = clientZkAuthCipher.createAuthCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, authCredential);
    assertEquals(presentation.serialize()[0], 1); // Check V2
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

    UUID uuid           = TEST_UUID;
    int  redemptionTime = (int)(Instant.now().truncatedTo(ChronoUnit.DAYS).getEpochSecond() / 86400);

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
    AuthCredentialResponse authCredentialResponse = serverZkAuth.issueAuthCredential(createSecureRandom(TEST_ARRAY_32_2), uuid, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredential         authCredential      = clientZkAuthCipher.receiveAuthCredential(uuid, redemptionTime, authCredentialResponse);

    // Create and decrypt user entry
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    UUID           plaintext      = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assertEquals(uuid, plaintext);

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

    UUID aci               = TEST_UUID;
    UUID pni               = TEST_UUID_1;
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
    AuthCredentialWithPniResponse authCredentialResponse = serverZkAuth.issueAuthCredentialWithPni(createSecureRandom(TEST_ARRAY_32_2), aci, pni, redemptionTime);

    // CLIENT
    // Receive credential
    ClientZkAuthOperations clientZkAuthCipher  = new ClientZkAuthOperations(serverPublicParams);
    ClientZkGroupCipher    clientZkGroupCipher = new ClientZkGroupCipher   (groupSecretParams );
    AuthCredentialWithPni  authCredential      = clientZkAuthCipher.receiveAuthCredentialWithPni(aci, pni, redemptionTime.getEpochSecond(), authCredentialResponse);

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
            clientZkAuthCipher.receiveAuthCredentialWithPni(pni, aci, redemptionTime.getEpochSecond(), authCredentialResponse);
            throw new AssertionError("Failed to catch invalid AuthCredentialWithPni 1");
        } catch (VerificationFailedException e) {
            // expected
        }

        byte[] temp = authCredentialResponse.serialize();
        temp[1]++;
        AuthCredentialWithPniResponse badResponse = new AuthCredentialWithPniResponse(temp);  
        try {
            clientZkAuthCipher.receiveAuthCredentialWithPni(aci, pni, redemptionTime.getEpochSecond(), badResponse);
            throw new AssertionError("Failed to catch invalid AuthCredentialWithPni 2");
        } catch (VerificationFailedException e) {
            // expected
        }
    }

    // Create and decrypt user entry
    UuidCiphertext aciCiphertext = clientZkGroupCipher.encryptUuid(aci);
    UUID           aciPlaintext  = clientZkGroupCipher.decryptUuid(aciCiphertext);
    assertEquals(aci, aciPlaintext);
    UuidCiphertext pniCiphertext = clientZkGroupCipher.encryptUuid(pni);
    UUID           pniPlaintext  = clientZkGroupCipher.decryptUuid(pniCiphertext);
    assertEquals(pni, pniPlaintext);

    // CLIENT - Create presentation
    AuthCredentialPresentation presentation = clientZkAuthCipher.createAuthCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, authCredential);
    assertEquals(presentation.serialize()[0], 2); // Check V3
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
  public void testProfileKeyIntegration() throws VerificationFailedException, InvalidInputException, UnsupportedEncodingException {

    UUID uuid           = TEST_UUID;

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
    ProfileKeyCommitment profileKeyCommitment = profileKey.getCommitment(uuid);

    // Create context and request
    ProfileKeyCredentialRequestContext context = clientZkProfileCipher.createProfileKeyCredentialRequestContext(createSecureRandom(TEST_ARRAY_32_3), uuid, profileKey);
    ProfileKeyCredentialRequest        request = context.getRequest();

    // CLIENT - deserialize test
    {
        new ProfileKeyCredentialRequestContext(context.serialize());
        try {
            byte[] temp = new byte[10];
            new ProfileKeyCredentialRequestContext(temp);
            throw new AssertionError("Failed to catch invalid ProfileKeyCredentialResponse deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }
        try {
            new ProfileKeyCredentialRequestContext(makeBadArray(context.serialize()));
            throw new AssertionError("Failed to catch invalid ProfileKeyCredentialRequestContext deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }

    // SERVER 
    ProfileKeyCredentialResponse response = serverZkProfile.issueProfileKeyCredential(createSecureRandom(TEST_ARRAY_32_4), request, uuid, profileKeyCommitment);

    // SERVER - verification test
    {
        byte[] temp = request.serialize();
        temp[4]++;  // We need a bad presentation that passes deserialization, this seems to work
        ProfileKeyCredentialRequest badRequest = new ProfileKeyCredentialRequest(temp);
        try {
            serverZkProfile.issueProfileKeyCredential(createSecureRandom(TEST_ARRAY_32_4), badRequest, uuid, profileKeyCommitment);
            throw new AssertionError("Failed to catch invalid ProfileKeyCredentialRequest");
        } catch (VerificationFailedException e) {
            // expected
        }
    }
   
    // CLIENT
    // Gets stored profile credential
    ClientZkGroupCipher  clientZkGroupCipher  = new ClientZkGroupCipher(groupSecretParams);
    ProfileKeyCredential profileKeyCredential = clientZkProfileCipher.receiveProfileKeyCredential(context, response);

    // Create encrypted UID and profile key
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    UUID           plaintext      = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assertEquals(plaintext, uuid);

    ProfileKeyCiphertext profileKeyCiphertext   = clientZkGroupCipher.encryptProfileKey(profileKey, uuid);
    ProfileKey           decryptedProfileKey    = clientZkGroupCipher.decryptProfileKey(profileKeyCiphertext, uuid);
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());

    // CLIENT - deserialize test
    {
        new ProfileKeyCiphertext(profileKeyCiphertext.serialize());
        try {
            byte[] temp = new byte[10];
            new ProfileKeyCiphertext(temp);
            throw new AssertionError("Failed to catch invalid ProfileKeyCiphertext deserialize 1");
        } catch (InvalidInputException e) {
            // expected
        }

        try {
            new ProfileKeyCiphertext(makeBadArray(profileKeyCiphertext.serialize()));
            throw new AssertionError("Failed to catch invalid ProfileKeyCiphertext deserialize 2");
        } catch (InvalidInputException e) {
            // expected
        }
    }

    // CLIENT - verify test
    {
        byte[] temp = profileKeyCiphertext.serialize();
        temp[2]++; // We need a bad ciphertext that passes deserialization, this seems to work
        try {
            clientZkGroupCipher.decryptProfileKey(new ProfileKeyCiphertext(temp), uuid);
            throw new AssertionError("Failed to catch invalid ProfileKeyCiphertext decrypt");
        } catch (VerificationFailedException e) {
            // expected
        }
    }

    ProfileKeyCredentialPresentation presentation = clientZkProfileCipher.createProfileKeyCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, profileKeyCredential);
    assertEquals(presentation.serialize()[0], 1); // Check V2
    assertEquals(presentation.getVersion(), ProfileKeyCredentialPresentation.Version.V2);
    assertArrayEquals(presentation.serialize(), profileKeyPresentationResultV2);

    // Verify presentation
    serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentation);
    UuidCiphertext uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize());

    ProfileKeyVersion pkvB = profileKey.getProfileKeyVersion(uuid);
    ProfileKeyVersion pkvC = new ProfileKeyVersion(pkvB.serialize());
    if (!pkvB.serialize().equals(pkvC.serialize()))
      throw new AssertionError();

    try {
        byte[] temp = presentation.serialize();
        temp[2]++;  // We need a bad presentation that passes deserializaton, this seems to work
        ProfileKeyCredentialPresentation presentationTemp = new ProfileKeyCredentialPresentation(temp);
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyProfileKeyCredentialPresentation should fail 1");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 0; // This interprets a V2 as V1, so should fail
        ProfileKeyCredentialPresentation presentationTemp = new ProfileKeyCredentialPresentation(temp);
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyProfileKeyCredentialPresentation should fail 2");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 2; // This interprets a V2 as a non-existent version, so should fail
        ProfileKeyCredentialPresentation presentationTemp = new ProfileKeyCredentialPresentation(temp);
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyProfileKeyCredentialPresentation should fail 3");
    } catch (InvalidInputException e) {
        // expected
    }

    try {
        // Test that V1 presentation parses successfully
        ProfileKeyCredentialPresentation presentationTemp = new ProfileKeyCredentialPresentation(profileKeyPresentationResultV1);
        assertEquals(presentationTemp.serialize()[0], 0); // Check V1
        assertEquals(presentationTemp.getVersion(), ProfileKeyCredentialPresentation.Version.V1);
        assertArrayEquals(presentationTemp.serialize(), profileKeyPresentationResultV1);
        serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyProfileKeyCredentialPresentation should fail on v1");
    } catch (VerificationFailedException e) {
        // expected
    }

  }

  @Test
  public void testExpiringProfileKeyIntegration() throws VerificationFailedException, InvalidInputException, UnsupportedEncodingException {

    UUID uuid           = TEST_UUID;

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
    ProfileKeyCommitment profileKeyCommitment = profileKey.getCommitment(uuid);

    // Create context and request
    ProfileKeyCredentialRequestContext context = clientZkProfileCipher.createProfileKeyCredentialRequestContext(createSecureRandom(TEST_ARRAY_32_3), uuid, profileKey);
    ProfileKeyCredentialRequest        request = context.getRequest();

    // SERVER 
    Instant expiration = Instant.now().truncatedTo(ChronoUnit.DAYS).plus(5, ChronoUnit.DAYS);
    ExpiringProfileKeyCredentialResponse response = serverZkProfile.issueExpiringProfileKeyCredential(createSecureRandom(TEST_ARRAY_32_4), request, uuid, profileKeyCommitment, expiration);

    // SERVER - verification test
    {
        byte[] temp = request.serialize();
        temp[4]++;  // We need a bad presentation that passes deserialization, this seems to work
        ProfileKeyCredentialRequest badRequest = new ProfileKeyCredentialRequest(temp);
        try {
            serverZkProfile.issueExpiringProfileKeyCredential(createSecureRandom(TEST_ARRAY_32_4), badRequest, uuid, profileKeyCommitment, expiration);
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
    UuidCiphertext uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    UUID           plaintext      = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assertEquals(plaintext, uuid);

    ProfileKeyCiphertext profileKeyCiphertext   = clientZkGroupCipher.encryptProfileKey(profileKey, uuid);
    ProfileKey           decryptedProfileKey    = clientZkGroupCipher.decryptProfileKey(profileKeyCiphertext, uuid);
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());

    assertEquals(expiration, profileKeyCredential.getExpirationTime());

    ProfileKeyCredentialPresentation presentation = clientZkProfileCipher.createProfileKeyCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, profileKeyCredential);
    assertEquals(presentation.serialize()[0], 2); // Check V3
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

  @Test @SuppressWarnings("deprecation")
  public void testPniIntegration() throws VerificationFailedException, InvalidInputException, UnsupportedEncodingException {

    UUID aci            = TEST_UUID;
    UUID pni            = TEST_UUID_1;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    ServerSecretParams serverSecretParams = ServerSecretParams.generate(createSecureRandom(TEST_ARRAY_32));
    ServerPublicParams serverPublicParams = serverSecretParams.getPublicParams();
    ServerZkProfileOperations serverZkProfile = new ServerZkProfileOperations(serverSecretParams);

    // CLIENT
    GroupMasterKey    masterKey         = new GroupMasterKey(TEST_ARRAY_32_1);
    GroupSecretParams groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(groupSecretParams.getMasterKey().serialize(), masterKey.serialize());

    GroupPublicParams         groupPublicParams     = groupSecretParams.getPublicParams();
    ClientZkProfileOperations clientZkProfileCipher = new ClientZkProfileOperations(serverPublicParams);

    ProfileKey           profileKey           = new ProfileKey(TEST_ARRAY_32_1);
    ProfileKeyCommitment profileKeyCommitment = profileKey.getCommitment(aci);

    // Create context and request
    PniCredentialRequestContext context = clientZkProfileCipher.createPniCredentialRequestContext(createSecureRandom(TEST_ARRAY_32_3), aci, pni, profileKey);
    ProfileKeyCredentialRequest request = context.getRequest();

    // SERVER
    PniCredentialResponse response = serverZkProfile.issuePniCredential(createSecureRandom(TEST_ARRAY_32_4), request, aci, pni, profileKeyCommitment);

    // CLIENT
    // Gets stored profile credential
    ClientZkGroupCipher clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    PniCredential       pniCredential       = clientZkProfileCipher.receivePniCredential(context, response);

    PniCredentialPresentation presentation = clientZkProfileCipher.createPniCredentialPresentation(createSecureRandom(TEST_ARRAY_32_5), groupSecretParams, pniCredential);
    assertEquals(presentation.serialize()[0], 1); // Check V2
    assertEquals(presentation.getVersion(), PniCredentialPresentation.Version.V2);

    assertArrayEquals(presentation.serialize(), pniPresentationResultV2);

    // Verify presentation
    serverZkProfile.verifyPniCredentialPresentation(groupPublicParams, presentation);
    UuidCiphertext aciCiphertextRecv = presentation.getAciCiphertext();
    assertArrayEquals(clientZkGroupCipher.encryptUuid(aci).serialize(), aciCiphertextRecv.serialize());
    UuidCiphertext pniCiphertextRecv = presentation.getPniCiphertext();
    assertArrayEquals(clientZkGroupCipher.encryptUuid(pni).serialize(), pniCiphertextRecv.serialize());

    try {
        byte[] temp = presentation.serialize();
        temp[2]++;  // We need a bad presentation that passes deserializaton, this seems to work
        PniCredentialPresentation presentationTemp = new PniCredentialPresentation(temp);
        serverZkProfile.verifyPniCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyPniCredentialPresentation should fail 1");
    } catch (VerificationFailedException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 0; // This interprets a V2 as V1, so should fail
        PniCredentialPresentation presentationTemp = new PniCredentialPresentation(temp);
        serverZkProfile.verifyPniCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyPniCredentialPresentation should fail 2");
    } catch (InvalidInputException e) {
        // expected
    }

    try {
        byte[] temp = presentation.serialize();
        temp[0] = 40; // This interprets a V2 as a non-existent version, so should fail
        PniCredentialPresentation presentationTemp = new PniCredentialPresentation(temp);
        serverZkProfile.verifyPniCredentialPresentation(groupPublicParams, presentationTemp);
        throw new AssertionError("verifyPniCredentialPresentation should fail 3");
    } catch (InvalidInputException e) {
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

  private void assertByteArray(String expectedAsHex, byte[] actual) {
    byte[] expectedBytes = Hex.fromStringCondensedAssert(expectedAsHex);

    assertArrayEquals(expectedBytes, actual);
  }

}


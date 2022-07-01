//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import { toUUID } from '../zkgroup/internal/UUIDUtil';

import {
  ServerSecretParams,
  ServerZkAuthOperations,
  GroupMasterKey,
  GroupSecretParams,
  ClientZkAuthOperations,
  ClientZkGroupCipher,
  ServerZkProfileOperations,
  ClientZkProfileOperations,
  ProfileKey,
  ProfileKeyVersion,
  ClientZkReceiptOperations,
  ServerZkReceiptOperations,
  ReceiptSerial,
} from '../zkgroup/';

function hexToBuffer(hex: string) {
  return Buffer.from(hex, 'hex');
}
function assertByteArray(hex: string, actual: Buffer) {
  const actualHex = actual.toString('hex');

  assert.strictEqual(hex, actualHex);
}
function assertArrayEquals(expected: Buffer, actual: Buffer) {
  const expectedHex = expected.toString('hex');
  const actualHex = actual.toString('hex');

  assert.strictEqual(expectedHex, actualHex);
}
function assertArrayNotEquals(expected: Buffer, actual: Buffer) {
  const expectedHex = expected.toString('hex');
  const actualHex = actual.toString('hex');

  assert.notEqual(expectedHex, actualHex);
}

describe('ZKGroup', () => {
  const TEST_ARRAY_16 = hexToBuffer('000102030405060708090a0b0c0d0e0f');
  const TEST_ARRAY_16_1 = hexToBuffer('6465666768696a6b6c6d6e6f70717273');
  const TEST_ARRAY_32 = hexToBuffer(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
  );
  const TEST_ARRAY_32_1 = hexToBuffer(
    '6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283'
  );
  const TEST_ARRAY_32_2 = hexToBuffer(
    'c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7'
  );
  const TEST_ARRAY_32_3 = Buffer.from([
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
  ]);
  const TEST_ARRAY_32_4 = Buffer.from([
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
  ]);
  const TEST_ARRAY_32_5 = hexToBuffer(
    '030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122'
  );
  const authPresentationResult = hexToBuffer(
    '01322f9100de0734550a81dc81724a81dbd3b1b43dbc1d552d53455911c2772f34a6356ca17c6d34d858391456af55d0ef841fbe1fa8c4ee810f21e0bb9f4ace4c5c48c72ebbeb2ccda5f7aa49aee6bc0051cdde166e0f8c5f1febd53a4437c570ee1aa223f5eb937db98f34e3653d85ec163f39847222a2dec4235ea41c47bb62028aae30945857ee77663079bcc4923d14a43ad4f6bc33715046f7bde52715375ca9f89be0e630d4bdaa211156d0306723f543b06f5e998447b962c8e9729b4cc00000000000000074d0eae8e4311a6ae3d2970ef198c398110462be47dd2f26e6559209ef6cc20001a05a0b319a172dbeb2293cc1e0e191cefb23e24cf0d6b4b5373a30044be10cb033674d631e17dfce09398f234e9d62e118a6077caea0ef8bf67d7d723db70fecf2098fa041317b7be9fdbb68b0f25f5c479d68bd917fc6f187c5bf7a58910231921fc43565232466325c039212362b6d1203ccaedf831dc7f9060dcaaffa02624042171f5f0e780b9f74cfa88a147f3f1c082f9ca8638af1788e7899cbae0c765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547440e20100'
  );

  const profileKeyPresentationResult = hexToBuffer(
    '01e0f49cef4f25c31d1bfdc4a328fd508d2222b6decee2a253cf71e8821e97cc3f86824f79b1884b43c67f854717b1a47f56c8ff50a1c07fddbf4f6e857027d548583b54079dd61d54cdd39cd4acae5f8b3bbfa2bb6b3502b69b36da77addddc145ef254a16f2baec1e3d7e8dc80730bc608fcd0e4d8cfef3330a496380c7ac648686b9c5b914d0a77ee84848aa970b2404450179b4022eef003387f6bdbcba30344cadfd5e3f1677caa2c785f4fefe042a1b2adf4f4b8fa6023e41d704bda901d3a697904770ac46e0e304cf19f91ce9ab0ed1ccad8a6febd72313455f139b9222e9a30a2265c6cd22ee5b907fc95967417a0d8ca338a5ee4d51bba78039c314e4001000000000000749d54772b8137e570157c068a5cfebb464b6c1133c72d9abfda72db421cd00561ac4eecb94313c6912013e32c322ea36743b01814fe919ca84b9aea9c78b10ba021506f7ad8c6625e87e07ce32b559036af6b67e2c0383a643cb93cdc2b9800e90588a18fcc449cd466c28c6db73507d8282dd00808b5927fee3336ed0a2202dfb1e176fece6a4104caa2a866c475209967638ea2f1466847da7301a77b9007dfb332a30e9bbfae8a8398165ec9dd4778214e0d6ed35a34071bdf3b3b19510ff2a617bc53eb0e6b0ddc501db027bb47e4f4127d7a0104945f3d3dc7ec1741038b9b80e2c7f131c519ee26ffcb7cb9d3556cd35a12bef1d4b376fc513197ba00ce8f012a0b374164222ba79a39e74e150813474ca6f87ba705c0f06e7b7068039c5edd9dd1a5ab6793ac211989907686b45650221187d4d59ae492679f3b4308765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547448c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746'
  );

  const pniPresentationResult = hexToBuffer(
    '01f887f403db1a80fa04043413233f56bf6c53bb078c16d24df93a219d7785696856d8f197a01c6e223d4aceed1d60b90b713f4556ab39403b84c51d724ca9aa44886d73be15fcebc933f835fc0f3210f8d7b8fa7940bf9069d50dc4ba83da8a0ed86d6c33cd99a25fe46906d655a7fec5fee500527a56ea5689d1765396907b153a86e40eb27b8120661dfe59bb17af1024ebd697c2c36c46f3a85f8dc6f92761b29c84256847b5f420386ac41d6d81f8e65a195f2ab7003c0fc22fd969870e2c5c4ad4a9de38a8bde73509c41e85accef59db69930972b1c3fcb9c9abd4c884a3e91b4c25b8fde3b5cac7c55442f996b3fd3712110c7dd71c847be552122b947402136b1c16fe18acba2e6a277dc57172ac79d189246060d50db1a7dc531d075ec9414f86e31a1b0406ce173b09c1eabbef2de117749b3c512499d5f91e4694e4001000000000000769c0c6c310ed2b8f4a1d1e6b853d83f5da8136e36605fd631979cc618d0e102cc82e9056d2031379de3e57c04530b20617d0b2418b8950c8a2394355c6d400f0e4f69b75942032067382ae244870f5859a35782cb81b1106c5aae58df1f110dbf761c3a52ad5e3a872f385c3056bf2be3d67826cf33bc743c1c25eed0eda20f21de773906657b26e09cf388da2333db60f768865e2405f4df4f48b640295e027625678a810dbf8111918f7b127fd9fb0b332531ec52069b98abf95bb4ae7307d96b9d50b6e734ff8af92d2c8417919795a46b97df7a692df4ea9b63810ef70dca68693bbec7e1f52409430da61cac9249ca02216a77b1f08e5951a50783ca088fa5992b5ecaf1413dfe45f9ef23b3c120994118b325763d66e60c9647cc380248a9da79e46c17b6bb03a23c3987cea86ac158d45b78f1f9b923472521ecb30e765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f525474fe74409060615679fc115473683d63abd9ced46c7f2ad736046de5a2c7d2522f122895597049cfd7cc5beb6dc72aa990ae9a62ec8e256a1cbf5f3f284233bb0748c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746'
  );

  it('testAuthIntegration', () => {
    const uuid = toUUID(TEST_ARRAY_16);
    const redemptionTime = 123456;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams = ServerSecretParams.generateWithRandom(
      TEST_ARRAY_32
    );
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkAuth = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(
      groupSecretParams.getMasterKey().serialize(),
      masterKey.serialize()
    );

    const groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    const authCredentialResponse = serverZkAuth.issueAuthCredentialWithRandom(
      TEST_ARRAY_32_2,
      uuid,
      redemptionTime
    );

    // CLIENT
    // Receive credential
    const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const authCredential = clientZkAuthCipher.receiveAuthCredential(
      uuid,
      redemptionTime,
      authCredentialResponse
    );

    // Create and decrypt user entry
    const uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    const plaintext = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assert.strictEqual(uuid, plaintext);

    // Create presentation
    const presentation = clientZkAuthCipher.createAuthCredentialPresentationWithRandom(
      TEST_ARRAY_32_5,
      groupSecretParams,
      authCredential
    );

    // Verify presentation
    const uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(
      uuidCiphertext.serialize(),
      uuidCiphertextRecv.serialize()
    );
    assert.isNull(presentation.getPniCiphertext());
    assert.deepEqual(
      presentation.getRedemptionTime(),
      new Date(redemptionTime * 86400 * 1000)
    );
    serverZkAuth.verifyAuthCredentialPresentation(
      groupPublicParams,
      presentation,
      new Date(redemptionTime * 86400 * 1000)
    );

    assertArrayEquals(presentation.serialize(), authPresentationResult);
  });

  it('testAuthWithPniIntegration', () => {
    const aci = toUUID(TEST_ARRAY_16);
    const pni = toUUID(TEST_ARRAY_16_1);
    const redemptionTime = 123456 * 86400;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams = ServerSecretParams.generateWithRandom(
      TEST_ARRAY_32
    );
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkAuth = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(
      groupSecretParams.getMasterKey().serialize(),
      masterKey.serialize()
    );

    const groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    const authCredentialResponse = serverZkAuth.issueAuthCredentialWithPniWithRandom(
      TEST_ARRAY_32_2,
      aci,
      pni,
      redemptionTime
    );

    // CLIENT
    // Receive credential
    const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const authCredential = clientZkAuthCipher.receiveAuthCredentialWithPni(
      aci,
      pni,
      redemptionTime,
      authCredentialResponse
    );

    // Create and decrypt user entry
    const aciCiphertext = clientZkGroupCipher.encryptUuid(aci);
    const aciPlaintext = clientZkGroupCipher.decryptUuid(aciCiphertext);
    assert.strictEqual(aci, aciPlaintext);
    const pniCiphertext = clientZkGroupCipher.encryptUuid(pni);
    const pniPlaintext = clientZkGroupCipher.decryptUuid(pniCiphertext);
    assert.strictEqual(pni, pniPlaintext);

    // Create presentation
    const presentation = clientZkAuthCipher.createAuthCredentialWithPniPresentationWithRandom(
      TEST_ARRAY_32_5,
      groupSecretParams,
      authCredential
    );

    // Verify presentation
    assertArrayEquals(
      aciCiphertext.serialize(),
      presentation.getUuidCiphertext().serialize()
    );
    const presentationPniCiphertext = presentation.getPniCiphertext();
    // Use a generic assertion instead of assert.isNotNull because TypeScript understands it.
    assert(presentationPniCiphertext !== null);
    assertArrayEquals(
      pniCiphertext.serialize(),
      presentationPniCiphertext.serialize()
    );
    assert.deepEqual(
      presentation.getRedemptionTime(),
      new Date(1000 * redemptionTime)
    );
    serverZkAuth.verifyAuthCredentialPresentation(
      groupPublicParams,
      presentation,
      new Date(1000 * redemptionTime)
    );
  });

  it('testProfileKeyIntegration', () => {
    const uuid = toUUID(TEST_ARRAY_16);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams = ServerSecretParams.generateWithRandom(
      TEST_ARRAY_32
    );
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkProfile = new ServerZkProfileOperations(serverSecretParams);

    // CLIENT
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(
      groupSecretParams.getMasterKey().serialize(),
      masterKey.serialize()
    );

    const groupPublicParams = groupSecretParams.getPublicParams();
    const clientZkProfileCipher = new ClientZkProfileOperations(
      serverPublicParams
    );

    const profileKey = new ProfileKey(TEST_ARRAY_32_1);
    const profileKeyCommitment = profileKey.getCommitment(uuid);

    // Create context and request
    const context = clientZkProfileCipher.createProfileKeyCredentialRequestContextWithRandom(
      TEST_ARRAY_32_3,
      uuid,
      profileKey
    );
    const request = context.getRequest();

    // SERVER
    const response = serverZkProfile.issueProfileKeyCredentialWithRandom(
      TEST_ARRAY_32_4,
      request,
      uuid,
      profileKeyCommitment
    );

    // CLIENT
    // Gets stored profile credential
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const profileKeyCredential = clientZkProfileCipher.receiveProfileKeyCredential(
      context,
      response
    );

    // Create encrypted UID and profile key
    const uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    const plaintext = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assert.strictEqual(plaintext, uuid);

    const profileKeyCiphertext = clientZkGroupCipher.encryptProfileKey(
      profileKey,
      uuid
    );
    const decryptedProfileKey = clientZkGroupCipher.decryptProfileKey(
      profileKeyCiphertext,
      uuid
    );
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());

    const presentation = clientZkProfileCipher.createProfileKeyCredentialPresentationWithRandom(
      TEST_ARRAY_32_5,
      groupSecretParams,
      profileKeyCredential
    );

    assertArrayEquals(presentation.serialize(), profileKeyPresentationResult);

    // Verify presentation
    serverZkProfile.verifyProfileKeyCredentialPresentation(
      groupPublicParams,
      presentation
    );
    const uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(
      uuidCiphertext.serialize(),
      uuidCiphertextRecv.serialize()
    );

    const pkvB = profileKey.getProfileKeyVersion(uuid);
    const pkvC = new ProfileKeyVersion(pkvB.serialize());
    assertArrayEquals(pkvB.serialize(), pkvC.serialize());
  });

  it('testExpiringProfileKeyIntegration', () => {
    const uuid = toUUID(TEST_ARRAY_16);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams = ServerSecretParams.generateWithRandom(
      TEST_ARRAY_32
    );
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkProfile = new ServerZkProfileOperations(serverSecretParams);

    // CLIENT
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    const groupPublicParams = groupSecretParams.getPublicParams();
    const clientZkProfileCipher = new ClientZkProfileOperations(
      serverPublicParams
    );

    const profileKey = new ProfileKey(TEST_ARRAY_32_1);
    const profileKeyCommitment = profileKey.getCommitment(uuid);

    // Create context and request
    const context = clientZkProfileCipher.createProfileKeyCredentialRequestContextWithRandom(
      TEST_ARRAY_32_3,
      uuid,
      profileKey
    );
    const request = context.getRequest();

    // SERVER
    const now = Math.floor(Date.now() / 1000);
    const startOfDay = now - (now % 86400);
    const expiration = startOfDay + 5 * 86400;
    const response = serverZkProfile.issueExpiringProfileKeyCredentialWithRandom(
      TEST_ARRAY_32_4,
      request,
      uuid,
      profileKeyCommitment,
      expiration
    );

    // CLIENT
    // Gets stored profile credential
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const profileKeyCredential = clientZkProfileCipher.receiveExpiringProfileKeyCredential(
      context,
      response
    );

    // Create encrypted UID and profile key
    const uuidCiphertext = clientZkGroupCipher.encryptUuid(uuid);
    const plaintext = clientZkGroupCipher.decryptUuid(uuidCiphertext);
    assert.strictEqual(plaintext, uuid);

    const profileKeyCiphertext = clientZkGroupCipher.encryptProfileKey(
      profileKey,
      uuid
    );
    const decryptedProfileKey = clientZkGroupCipher.decryptProfileKey(
      profileKeyCiphertext,
      uuid
    );
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());
    assert.deepEqual(
      profileKeyCredential.getExpirationTime(),
      new Date(expiration * 1000)
    );

    const presentation = clientZkProfileCipher.createExpiringProfileKeyCredentialPresentationWithRandom(
      TEST_ARRAY_32_5,
      groupSecretParams,
      profileKeyCredential
    );

    // Verify presentation
    serverZkProfile.verifyProfileKeyCredentialPresentation(
      groupPublicParams,
      presentation
    );
    serverZkProfile.verifyProfileKeyCredentialPresentation(
      groupPublicParams,
      presentation,
      new Date(expiration * 1000 - 5)
    );
    const uuidCiphertextRecv = presentation.getUuidCiphertext();
    assertArrayEquals(
      uuidCiphertext.serialize(),
      uuidCiphertextRecv.serialize()
    );

    // Test expiration
    assert.throws(() =>
      serverZkProfile.verifyProfileKeyCredentialPresentation(
        groupPublicParams,
        presentation,
        new Date(expiration * 1000)
      )
    );
    assert.throws(() =>
      serverZkProfile.verifyProfileKeyCredentialPresentation(
        groupPublicParams,
        presentation,
        new Date(expiration * 1000 + 5)
      )
    );
  });

  it('testPniIntegration', () => {
    const aci = toUUID(TEST_ARRAY_16);
    const pni = toUUID(TEST_ARRAY_16_1);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams = ServerSecretParams.generateWithRandom(
      TEST_ARRAY_32
    );
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkProfile = new ServerZkProfileOperations(serverSecretParams);

    // CLIENT
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assertArrayEquals(
      groupSecretParams.getMasterKey().serialize(),
      masterKey.serialize()
    );

    const groupPublicParams = groupSecretParams.getPublicParams();
    const clientZkProfileCipher = new ClientZkProfileOperations(
      serverPublicParams
    );

    const profileKey = new ProfileKey(TEST_ARRAY_32_1);
    const profileKeyCommitment = profileKey.getCommitment(aci);

    // Create context and request
    const context = clientZkProfileCipher.createPniCredentialRequestContextWithRandom(
      TEST_ARRAY_32_3,
      aci,
      pni,
      profileKey
    );
    const request = context.getRequest();

    // SERVER
    const response = serverZkProfile.issuePniCredentialWithRandom(
      TEST_ARRAY_32_4,
      request,
      aci,
      pni,
      profileKeyCommitment
    );

    // CLIENT
    // Gets stored profile credential
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const pniCredential = clientZkProfileCipher.receivePniCredential(
      context,
      response
    );

    const presentation = clientZkProfileCipher.createPniCredentialPresentationWithRandom(
      TEST_ARRAY_32_5,
      groupSecretParams,
      pniCredential
    );

    assertArrayEquals(presentation.serialize(), pniPresentationResult);

    // Verify presentation
    serverZkProfile.verifyPniCredentialPresentation(
      groupPublicParams,
      presentation
    );
    const aciCiphertextRecv = presentation.getAciCiphertext();
    assertArrayEquals(
      clientZkGroupCipher.encryptUuid(aci).serialize(),
      aciCiphertextRecv.serialize()
    );
    const pniCiphertextRecv = presentation.getPniCiphertext();
    assertArrayEquals(
      clientZkGroupCipher.encryptUuid(pni).serialize(),
      pniCiphertextRecv.serialize()
    );
  });

  it('testServerSignatures', () => {
    const serverSecretParams = ServerSecretParams.generateWithRandom(
      TEST_ARRAY_32
    );
    const serverPublicParams = serverSecretParams.getPublicParams();

    const message = TEST_ARRAY_32_1;

    const signature = serverSecretParams.signWithRandom(
      TEST_ARRAY_32_2,
      message
    );
    serverPublicParams.verifySignature(message, signature);
    assertByteArray(
      '87d354564d35ef91edba851e0815612e864c227a0471d50c270698604406d003a55473f576cf241fc6b41c6b16e5e63b333c02fe4a33858022fdd7a4ab367b06',
      signature.serialize()
    );

    const alteredMessage = Buffer.from(message);
    alteredMessage[0] ^= 1;

    assertArrayNotEquals(message, alteredMessage);

    try {
      serverPublicParams.verifySignature(alteredMessage, signature);
      assert.fail('signature validation should have failed!');
    } catch (error) {
      // good
    }
  });

  it('testGroupIdentifier', () => {
    const groupSecretParams = GroupSecretParams.generateWithRandom(
      TEST_ARRAY_32
    );
    const _groupPublicParams = groupSecretParams.getPublicParams();
    // assertByteArray('31f2c60f86f4c5996e9e2568355591d9', groupPublicParams.getGroupIdentifier().serialize());
  });

  it('testInvalidSerialized', () => {
    const ckp = Buffer.alloc(289);
    ckp.fill(-127);
    assert.throws(() => new GroupSecretParams(ckp));
  });

  it('testWrongSizeSerialized', () => {
    const ckp = Buffer.alloc(5);
    ckp.fill(-127);
    assert.throws(() => new GroupSecretParams(ckp));
  });

  it('testBlobEncryption', () => {
    const groupSecretParams = GroupSecretParams.generate();
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    const plaintext = Buffer.from([0, 1, 2, 3, 4]);
    const ciphertext = clientZkGroupCipher.encryptBlob(plaintext);
    const plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext);
    assertArrayEquals(plaintext, plaintext2);
  });

  it('testBlobEncryptionWithRandom', () => {
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    const plaintext = hexToBuffer('0102030405060708111213141516171819');
    const ciphertext = hexToBuffer(
      'dd4d032ca9bb75a4a78541b90cb4e95743f3b0dabfc7e11101b098e34f6cf6513940a04c1f20a302692afdc7087f10196000'
    );
    const ciphertextPaddedWith257 = hexToBuffer(
      '5cb5b7bff06e85d929f3511fd194e638cf32a47663868bc8e64d98fb1bbe435ebd21c763ce2d42e85a1b2c169f12f9818ddadcf4b491398b7c5d46a224e1582749f5e2a4a2294caaaaab843a1b7cf6426fd543d09ff32a4ba5f319ca4442b4da34b3e2b5b4f8a52fdc4b484ea86b33db3ebb758dbd9614178f0e4e1f9b2b914f1e786936b62ed2b58b7ae3cb3e7ae0835b9516959837406662b85eac740cef83b60b5aaeaaab95643c2bef8ce87358fabff9d690052beb9e52d0c947e7c986b2f3ce3b7161cec72c08e2c4ade3debe3792d736c0457bc352afb8b6caa48a5b92c1ec05ba808ba8f94c6572ebbf29818912344987573de419dbcc7f1ea0e4b2dd4077b76b381819747ac332e46fa23abfc3338e2f4b081a8a53cba0988eef116764d944f1ce3f20a302692afdc7087f10196000'
    );

    const ciphertext2 = clientZkGroupCipher.encryptBlobWithRandom(
      TEST_ARRAY_32_2,
      plaintext
    );
    const plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext2);

    assertArrayEquals(plaintext, plaintext2);
    assertArrayEquals(ciphertext, ciphertext2);

    const plaintext257 = clientZkGroupCipher.decryptBlob(
      ciphertextPaddedWith257
    );
    assertArrayEquals(plaintext, plaintext257);
  });

  it('testReceiptFlow', () => {
    const serverSecretParams = ServerSecretParams.generateWithRandom(
      TEST_ARRAY_32
    );
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverOps = new ServerZkReceiptOperations(serverSecretParams);
    const clientOps = new ClientZkReceiptOperations(serverPublicParams);
    const receiptSerial = new ReceiptSerial(
      hexToBuffer('00112233445566778899aabbccddeeff')
    );

    // client
    const context = clientOps.createReceiptCredentialRequestContext(
      receiptSerial
    );
    const request = context.getRequest();

    // issuance server
    const receiptExpirationTime = 31337;
    const receiptLevel = BigInt('3');
    const response = serverOps.issueReceiptCredential(
      request,
      receiptExpirationTime,
      receiptLevel
    );

    // client
    const credential = clientOps.receiveReceiptCredential(context, response);
    assert(receiptExpirationTime == credential.getReceiptExpirationTime());
    assert(receiptLevel == credential.getReceiptLevel());
    const presentation = clientOps.createReceiptCredentialPresentation(
      credential
    );

    // redemption server
    serverOps.verifyReceiptCredentialPresentation(presentation);
  });
});

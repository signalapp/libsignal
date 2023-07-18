//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';

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
  ClientZkReceiptOperations,
  ServerZkReceiptOperations,
  ReceiptSerial,
  GenericServerSecretParams,
  CreateCallLinkCredentialRequestContext,
  CallLinkSecretParams,
  CallLinkAuthCredentialResponse,
} from '../zkgroup/';
import { Aci, Pni } from '../Address';

const SECONDS_PER_DAY = 86400;

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
  const TEST_UUID = 'dc249e7a-56ea-49cd-abce-aa3a0d65f6f0';
  const TEST_UUID_1 = '18c7e848-2213-40c1-bd6b-3b69a82dd1f5';
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
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  ]);
  const TEST_ARRAY_32_4 = Buffer.from([
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
  ]);
  const TEST_ARRAY_32_5 = hexToBuffer(
    '030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122'
  );

  it('testAuthIntegration', () => {
    const userId = Aci.fromUuid(TEST_UUID);
    const redemptionTime = 123456;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
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
      userId,
      redemptionTime
    );

    // CLIENT
    // Receive credential
    const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const authCredential = clientZkAuthCipher.receiveAuthCredential(
      userId,
      redemptionTime,
      authCredentialResponse
    );

    // Create and decrypt user entry
    const uuidCiphertext = clientZkGroupCipher.encryptServiceId(userId);
    const plaintext = clientZkGroupCipher.decryptServiceId(uuidCiphertext);
    assert.isTrue(plaintext.isEqual(userId));

    // Create presentation
    const presentation =
      clientZkAuthCipher.createAuthCredentialPresentationWithRandom(
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
      new Date(redemptionTime * SECONDS_PER_DAY * 1000)
    );
    serverZkAuth.verifyAuthCredentialPresentation(
      groupPublicParams,
      presentation,
      new Date(redemptionTime * SECONDS_PER_DAY * 1000)
    );
  });

  it('testAuthWithPniIntegration', () => {
    const aci = Aci.fromUuid(TEST_UUID);
    const pni = Pni.fromUuid(TEST_UUID_1);
    const redemptionTime = 123456 * SECONDS_PER_DAY;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
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
    const authCredentialResponse =
      serverZkAuth.issueAuthCredentialWithPniAsServiceIdWithRandom(
        TEST_ARRAY_32_2,
        aci,
        pni,
        redemptionTime
      );

    // CLIENT
    // Receive credential
    const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const authCredential =
      clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(
        aci,
        pni,
        redemptionTime,
        authCredentialResponse
      );
    assert.throws(() =>
      clientZkAuthCipher.receiveAuthCredentialWithPniAsAci(
        aci,
        pni,
        redemptionTime,
        authCredentialResponse
      )
    );

    // Create and decrypt user entry
    const aciCiphertext = clientZkGroupCipher.encryptServiceId(aci);
    const aciPlaintext = clientZkGroupCipher.decryptServiceId(aciCiphertext);
    assert(aci.isEqual(aciPlaintext));
    const pniCiphertext = clientZkGroupCipher.encryptServiceId(pni);
    const pniPlaintext = clientZkGroupCipher.decryptServiceId(pniCiphertext);
    assert(pni.isEqual(pniPlaintext));

    // Create presentation
    const presentation =
      clientZkAuthCipher.createAuthCredentialWithPniPresentationWithRandom(
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

  it('testAuthWithPniAsAciIntegration', () => {
    const aci = Aci.fromUuid(TEST_UUID);
    const pni = Pni.fromUuid(TEST_UUID_1);
    const redemptionTime = 123456 * SECONDS_PER_DAY;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
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
    const authCredentialResponse =
      serverZkAuth.issueAuthCredentialWithPniAsAciWithRandom(
        TEST_ARRAY_32_2,
        aci,
        pni,
        redemptionTime
      );

    // CLIENT
    // Receive credential
    const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const authCredential = clientZkAuthCipher.receiveAuthCredentialWithPniAsAci(
      aci,
      pni,
      redemptionTime,
      authCredentialResponse
    );
    assert.throws(() =>
      clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(
        aci,
        pni,
        redemptionTime,
        authCredentialResponse
      )
    );

    // Create and decrypt user entry
    const aciCiphertext = clientZkGroupCipher.encryptServiceId(aci);
    const aciPlaintext = clientZkGroupCipher.decryptServiceId(aciCiphertext);
    assert(aci.isEqual(aciPlaintext));
    const pniAsAci = Aci.fromUuidBytes(pni.getRawUuidBytes());
    const pniCiphertext = clientZkGroupCipher.encryptServiceId(pniAsAci);
    const pniPlaintext = clientZkGroupCipher.decryptServiceId(pniCiphertext);
    assert(pniAsAci.isEqual(pniPlaintext));

    // Create presentation
    const presentation =
      clientZkAuthCipher.createAuthCredentialWithPniPresentationWithRandom(
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

  it('testExpiringProfileKeyIntegration', () => {
    const userId = Aci.fromUuid(TEST_UUID);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
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
    const profileKeyCommitment = profileKey.getCommitment(userId);

    // Create context and request
    const context =
      clientZkProfileCipher.createProfileKeyCredentialRequestContextWithRandom(
        TEST_ARRAY_32_3,
        userId,
        profileKey
      );
    const request = context.getRequest();

    // SERVER
    const now = Math.floor(Date.now() / 1000);
    const startOfDay = now - (now % SECONDS_PER_DAY);
    const expiration = startOfDay + 5 * SECONDS_PER_DAY;
    const response =
      serverZkProfile.issueExpiringProfileKeyCredentialWithRandom(
        TEST_ARRAY_32_4,
        request,
        userId,
        profileKeyCommitment,
        expiration
      );

    // CLIENT
    // Gets stored profile credential
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const profileKeyCredential =
      clientZkProfileCipher.receiveExpiringProfileKeyCredential(
        context,
        response
      );

    // Create encrypted UID and profile key
    const uuidCiphertext = clientZkGroupCipher.encryptServiceId(userId);
    const plaintext = clientZkGroupCipher.decryptServiceId(uuidCiphertext);
    assert(plaintext.isEqual(userId));

    const profileKeyCiphertext = clientZkGroupCipher.encryptProfileKey(
      profileKey,
      userId
    );
    const decryptedProfileKey = clientZkGroupCipher.decryptProfileKey(
      profileKeyCiphertext,
      userId
    );
    assertArrayEquals(profileKey.serialize(), decryptedProfileKey.serialize());
    assert.deepEqual(
      profileKeyCredential.getExpirationTime(),
      new Date(expiration * 1000)
    );

    const presentation =
      clientZkProfileCipher.createExpiringProfileKeyCredentialPresentationWithRandom(
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

  it('testServerSignatures', () => {
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
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
    const groupSecretParams =
      GroupSecretParams.generateWithRandom(TEST_ARRAY_32);
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
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverOps = new ServerZkReceiptOperations(serverSecretParams);
    const clientOps = new ClientZkReceiptOperations(serverPublicParams);
    const receiptSerial = new ReceiptSerial(
      hexToBuffer('00112233445566778899aabbccddeeff')
    );

    // client
    const context =
      clientOps.createReceiptCredentialRequestContext(receiptSerial);
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
    const presentation =
      clientOps.createReceiptCredentialPresentation(credential);

    // redemption server
    serverOps.verifyReceiptCredentialPresentation(presentation);
  });

  it('testCreateCallLinkCredential', () => {
    const serverSecretParams =
      GenericServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();

    const clientSecretParams =
      CallLinkSecretParams.deriveFromRootKey(TEST_ARRAY_32_1);
    const clientPublicParams = clientSecretParams.getPublicParams();

    // client
    const roomId = TEST_ARRAY_32_2;
    const context = CreateCallLinkCredentialRequestContext.forRoomIdWithRandom(
      roomId,
      TEST_ARRAY_32_3
    );
    const request = context.getRequest();

    // issuance server
    const userId = Aci.fromUuid(TEST_UUID);
    const now = Math.floor(Date.now() / 1000);
    const startOfDay = now - (now % SECONDS_PER_DAY);
    const response = request.issueCredentialWithRandom(
      userId,
      startOfDay,
      serverSecretParams,
      TEST_ARRAY_32_4
    );

    // client
    const credential = context.receive(response, userId, serverPublicParams);
    const presentation = credential.presentWithRandom(
      roomId,
      userId,
      serverPublicParams,
      clientSecretParams,
      TEST_ARRAY_32_5
    );

    // redemption server
    presentation.verify(roomId, serverSecretParams, clientPublicParams);
    presentation.verify(
      roomId,
      serverSecretParams,
      clientPublicParams,
      new Date(1000 * (startOfDay + SECONDS_PER_DAY))
    );

    assert.throws(() =>
      presentation.verify(
        roomId,
        serverSecretParams,
        clientPublicParams,
        new Date(1000 * (startOfDay + 30 * 60 * 60))
      )
    );
  });

  it('testCallLinkAuthCredential', () => {
    const serverSecretParams =
      GenericServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();

    const clientSecretParams =
      CallLinkSecretParams.deriveFromRootKey(TEST_ARRAY_32_1);
    const clientPublicParams = clientSecretParams.getPublicParams();

    // issuance server
    const userId = Aci.fromUuid(TEST_UUID);
    const now = Math.floor(Date.now() / 1000);
    const startOfDay = now - (now % SECONDS_PER_DAY);
    const response = CallLinkAuthCredentialResponse.issueCredentialWithRandom(
      userId,
      startOfDay,
      serverSecretParams,
      TEST_ARRAY_32_4
    );

    // client
    const credential = response.receive(userId, startOfDay, serverPublicParams);
    const presentation = credential.presentWithRandom(
      userId,
      startOfDay,
      serverPublicParams,
      clientSecretParams,
      TEST_ARRAY_32_5
    );

    // redemption server
    presentation.verify(serverSecretParams, clientPublicParams);
    presentation.verify(
      serverSecretParams,
      clientPublicParams,
      new Date(1000 * (startOfDay + SECONDS_PER_DAY))
    );

    assert.throws(() =>
      presentation.verify(
        serverSecretParams,
        clientPublicParams,
        new Date(1000 * (startOfDay + 3 * SECONDS_PER_DAY))
      )
    );

    // Client
    assert.isTrue(
      userId.isEqual(clientSecretParams.decryptUserId(presentation.getUserId()))
    );
  });

  it('testDeriveProfileKey', () => {
    const expectedAccessKey = hexToBuffer('5a723acee52c5ea02b92a3a360c09595');
    const profileKey = Buffer.alloc(32, 0x02);

    const result = new ProfileKey(profileKey).deriveAccessKey();
    assertArrayEquals(expectedAccessKey, result);
  });
});

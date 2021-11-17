//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import { toUUID } from '../zkgroup/internal/UUIDUtil';

import ServerSecretParams from '../zkgroup/ServerSecretParams';
import ServerZkAuthOperations from '../zkgroup/auth/ServerZkAuthOperations';
import GroupMasterKey from '../zkgroup/groups/GroupMasterKey';
import GroupSecretParams from '../zkgroup/groups/GroupSecretParams';
import ClientZkAuthOperations from '../zkgroup/auth/ClientZkAuthOperations';
import ClientZkGroupCipher from '../zkgroup/groups/ClientZkGroupCipher';
import ServerZkProfileOperations from '../zkgroup/profiles/ServerZkProfileOperations';
import ClientZkProfileOperations from '../zkgroup/profiles/ClientZkProfileOperations';
import ProfileKey from '../zkgroup/profiles/ProfileKey';
import ProfileKeyVersion from '../zkgroup/profiles/ProfileKeyVersion';
import ClientZkReceiptOperations from '../zkgroup/receipts/ClientZkReceiptOperations';
import ServerZkReceiptOperations from '../zkgroup/receipts/ServerZkReceiptOperations';
import ReceiptSerial from '../zkgroup/receipts/ReceiptSerial';

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
    '000cde979737ed30bbeb16362e4e076945ce02069f727b0ed4c3c33c011e82546e1cdf081fbdf37c03a851ad060bdcbf6378cb4cb16dc3154d08de5439b5323203729d1841b517033af2fd177d30491c138ae723655734f6e5cc01c00696f4e92096d8c33df26ba2a820d42e9735d30f8eeef96d399079073c099f7035523bfe716638659319d3c36ad34c00ef8850f663c4d93030235074312a8878b6a5c5df4fbc7d32935278bfa5996b44ab75d6f06f4c30b98640ad5de74742656c8977567de000000000000000fde69f82ad2dcb4909650ac6b2573841af568fef822b32b45f625a764691a704d11b6f385261468117ead57fa623338e21c66ed846ab65809fcac158066d8e0e444077b99540d886e7dc09555dd6faea2cd3697f1e089f82d54e5d0fe4a185008b5cbc3979391ad71686bc03be7b00ea7e42c08d9f1d75c3a56c27ae2467b80636c0b5343eda7cd578ba88ddb7a0766568477fed63cf531862122c6c15b4a707973d41782cfc0ef4fe6c3115988a2e339015938d2df0a5d30237a2592cc10c05a9e4ef6b695bca99736b1a49ea39606a381ecfb05efe60d28b54823ec5a3680c765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547440e20100'
  );

  const profileKeyPresentationResult = hexToBuffer(
    '00c4d19bca1ae844585168869da4133e0e0bb59f2ce17b7ac65bff5da9610eca103429d8022a94bae2b5b1057b5595b8ad70bfc2d0e1ad662cb75e6bae0782be6f00e3db793bc28561f0196c2e74da6f303fa8bcb70c94096671b73f7b3a95fb002200d5b9180fa0ef7d3014d01344145b4d38480d72ff25c24294e305e5705072e0d32cc4e84f5caf31486089a4b934c80c92eba43472ff23a5af93c397535d33801f0e6fc6eb2ee0d117f03bb4fd38a8b9c88d94708131f38742ca804a3cfc4f9476bc2d03f53d17001c36478afbe9cc535a224b2df6b2b08bef06cbc7d4dc42ccfc3459f7ac5c4419ae9f3c8a161d554d047778943216240858da3b1101984c40010000000000007a01eea6b2adad14d71ab8b8e411bef3c596e954b70e4031570cb1abd7e932083241f1caca3116708fa4319fbbdfe351376c23644ae09a42f0155db4996c9d0c7ffc8521c1914c0e1a20ae51e65df64dd5e6e5985b3d9d31732046d2d77f9c08aaccf056b84026073976eec6164cbdaee5d9e76e497f0c290af681cabd5c5101282abb26c3680d6087ce053310fe8a94f59d8ae23caac5fc0ed0c379888abf028a6f29f89d4fe2acc1706341b2245ba1885bca57e1e27ccf7ed79371500965009f960c2ba00fad3e93383b87ce119cac0b3360eb99284ce78e2cbed680f7960373e0ab75c190254160c2353614109489e653c9b2e1c93f92c7c5ad583d987a04bd3541b24485c33ea49bac43c87c4ab3efde2e2d7ec10a40be544199f925b20b2c55542bc56410571e41cd8e0286f609a66768b5061ccb4777af32309928dd09765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547448c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746'
  );

  const pniPresentationResult = hexToBuffer(
    '00fecc5f71d40dbd45912d0de9c1ed033c7eb1c4755e19cb6241ede6a6a99f65545e870a806854c5000d436db601a89f72b9b399f0efa277473716e8bc20c984766250937555604f2d2fcdd263c60f2f72b5a04d9bbbc6f95c78085f81aaf07d3316a2dbd1ef85bb642d5da6d00d03fed8097276bf17a113a44018d773c9116c33ac86837d4f5c41fb70153f3d655c0b68982fae01113460db75ea7099ef7e910cbe0bd606870df55522f9d0b1bee1b1ab2f3b9cd3563a422684ebcfdb1fdada27acb4d48c7db9c6b1389c6742a8f8257bb70f5430feb4a438007fb33e7910da3b9a0997d7d35c6c93a8d45949d01f88b497c822b0127b3fc57cfaee90bcf7d41914f6f0f8fa0acd82e004caaad1c9feec2fb67f58936ae7a92a285dc15b23486a0272e864f3ae9769d650fdd0898739ad28e259e8dae73907caa8ff69a53a851e4001000000000000f26c704b8daf38a464810eca8589541521e053221dd830866bf77da025cdc2041e33f73e42c70387709acbac0df46d0155e6bf6f7952ddc3289a16ca682e740df7403cc12cbe0cd54a7b0de08eec4f7cdce52996880ef5db74bcc4e8e78d620da4d21ff137b29df3a1a08d14b9224c91ef05a1ac0a7cfe142b227853c90bb90db0cf3d6311560e49ca52983f9efc54ecb61f552d6a85088871ef4d0f5862dd04aff93fd97b7816181d38bcb30f71eaeb9eff2ba630916eac355f45703a8c780e8579b2793d4fb72e001d15e23bedcb3c827fc559ef7adb6da2ec33291b86bf0db2ad4a3a0cb9233d3af967d9301505b88d157b3436ae6122696718d812b27002cdce4c807610f2de7cec4a03933da64a6319eab4ac0630c99d0e62779974e8038ff5053275378c1b41dd7bb5f8f4c11daa4cd19fdec4d0222850c606857c990e765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f525474fe74409060615679fc115473683d63abd9ced46c7f2ad736046de5a2c7d2522f122895597049cfd7cc5beb6dc72aa990ae9a62ec8e256a1cbf5f3f284233bb0748c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746'
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
    assert.strictEqual(presentation.getRedemptionTime(), redemptionTime);
    serverZkAuth.verifyAuthCredentialPresentation(
      groupPublicParams,
      presentation
    );

    assertArrayEquals(presentation.serialize(), authPresentationResult);
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
    const receiptExpirationTime = BigInt('31337');
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

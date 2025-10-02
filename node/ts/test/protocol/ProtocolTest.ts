//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as SignalClient from '../../index.js';
import * as util from '../util.js';

import { assert, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import Chance from 'chance';
import { Buffer } from 'node:buffer';

import TestStores, {
  InMemoryIdentityKeyStore,
  InMemoryKyberPreKeyStore,
  InMemoryPreKeyStore,
  InMemorySenderKeyStore,
  InMemorySessionStore,
  InMemorySignedPreKeyStore,
} from './TestStores.js';

use(chaiAsPromised);
util.initLogger();

const chance = Chance();

it('Fingerprint', () => {
  const aliceKey = SignalClient.PublicKey.deserialize(
    Buffer.from(
      '0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868',
      'hex'
    )
  );
  const aliceIdentifier = Buffer.from('+14152222222', 'utf8');
  const bobKey = SignalClient.PublicKey.deserialize(
    Buffer.from(
      '05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b',
      'hex'
    )
  );
  const bobIdentifier = Buffer.from('+14153333333', 'utf8');
  const iterations = 5200;
  const aFprint1 = SignalClient.Fingerprint.new(
    iterations,
    1,
    aliceIdentifier,
    aliceKey,
    bobIdentifier,
    bobKey
  );

  util.assertByteArray(
    '080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d',
    aFprint1.scannableFingerprint().toBuffer()
  );

  assert.deepEqual(
    aFprint1.displayableFingerprint().toString(),
    '300354477692869396892869876765458257569162576843440918079131'
  );

  const bFprint1 = SignalClient.Fingerprint.new(
    iterations,
    1,
    bobIdentifier,
    bobKey,
    aliceIdentifier,
    aliceKey
  );

  util.assertByteArray(
    '080112220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df',
    bFprint1.scannableFingerprint().toBuffer()
  );
  assert.deepEqual(
    bFprint1.displayableFingerprint().toString(),
    '300354477692869396892869876765458257569162576843440918079131'
  );

  assert(
    aFprint1.scannableFingerprint().compare(bFprint1.scannableFingerprint())
  );
  assert(
    bFprint1.scannableFingerprint().compare(aFprint1.scannableFingerprint())
  );

  assert.isNotTrue(
    aFprint1.scannableFingerprint().compare(aFprint1.scannableFingerprint())
  );
  assert.isNotTrue(
    bFprint1.scannableFingerprint().compare(bFprint1.scannableFingerprint())
  );
});

it('DecryptionErrorMessage', async () => {
  const aKeys = new InMemoryIdentityKeyStore();
  const bKeys = new InMemoryIdentityKeyStore();

  const aSess = new InMemorySessionStore();
  const bSess = new InMemorySessionStore();

  const bPreK = new InMemoryPreKeyStore();
  const bSPreK = new InMemorySignedPreKeyStore();
  const bKyberStore = new InMemoryKyberPreKeyStore();

  const bPreKey = SignalClient.PrivateKey.generate();
  const bSPreKey = SignalClient.PrivateKey.generate();

  const aIdentityKey = await aKeys.getIdentityKey();
  const bIdentityKey = await bKeys.getIdentityKey();

  const aE164 = '+14151111111';

  const aDeviceId = 1;
  const bDeviceId = 3;

  const aUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
  const bUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

  const trustRoot = SignalClient.PrivateKey.generate();
  const serverKey = SignalClient.PrivateKey.generate();

  const serverCert = SignalClient.ServerCertificate.new(
    1,
    serverKey.getPublicKey(),
    trustRoot
  );

  const expires = 1605722925;
  const senderCert = SignalClient.SenderCertificate.new(
    aUuid,
    aE164,
    aDeviceId,
    aIdentityKey.getPublicKey(),
    expires,
    serverCert,
    serverKey
  );

  const bRegistrationId = await bKeys.getLocalRegistrationId();
  const bPreKeyId = 31337;
  const bSignedPreKeyId = 22;

  const bSignedPreKeySig = bIdentityKey.sign(
    bSPreKey.getPublicKey().serialize()
  );

  const bKyberPrekeyId = 777;
  const bKyberKeyPair = SignalClient.KEMKeyPair.generate();
  const bKyberPrekeySignature = bIdentityKey.sign(
    bKyberKeyPair.getPublicKey().serialize()
  );

  const bPreKeyBundle = SignalClient.PreKeyBundle.new(
    bRegistrationId,
    bDeviceId,
    bPreKeyId,
    bPreKey.getPublicKey(),
    bSignedPreKeyId,
    bSPreKey.getPublicKey(),
    bSignedPreKeySig,
    bIdentityKey.getPublicKey(),
    bKyberPrekeyId,
    bKyberKeyPair.getPublicKey(),
    bKyberPrekeySignature
  );

  const bPreKeyRecord = SignalClient.PreKeyRecord.new(
    bPreKeyId,
    bPreKey.getPublicKey(),
    bPreKey
  );
  await bPreK.savePreKey(bPreKeyId, bPreKeyRecord);

  const bSPreKeyRecord = SignalClient.SignedPreKeyRecord.new(
    bSignedPreKeyId,
    42, // timestamp
    bSPreKey.getPublicKey(),
    bSPreKey,
    bSignedPreKeySig
  );
  await bSPreK.saveSignedPreKey(bSignedPreKeyId, bSPreKeyRecord);

  const bKyberPreKeyRecord = SignalClient.KyberPreKeyRecord.new(
    bKyberPrekeyId,
    42, // timestamp
    bKyberKeyPair,
    bKyberPrekeySignature
  );
  await bKyberStore.saveKyberPreKey(bKyberPrekeyId, bKyberPreKeyRecord);

  // Set up the session with a message from A to B.

  const bAddress = SignalClient.ProtocolAddress.new(bUuid, bDeviceId);
  await SignalClient.processPreKeyBundle(bPreKeyBundle, bAddress, aSess, aKeys);

  const aPlaintext = Buffer.from('hi there', 'utf8');

  const aCiphertext = await SignalClient.sealedSenderEncryptMessage(
    aPlaintext,
    bAddress,
    senderCert,
    aSess,
    aKeys
  );

  await SignalClient.sealedSenderDecryptMessage(
    aCiphertext,
    trustRoot.getPublicKey(),
    43, // timestamp,
    null,
    bUuid,
    bDeviceId,
    bSess,
    bKeys,
    bPreK,
    bSPreK,
    bKyberStore
  );

  // Pretend to send a message from B back to A that "fails".
  const aAddress = SignalClient.ProtocolAddress.new(aUuid, aDeviceId);
  const bCiphertext = await SignalClient.signalEncrypt(
    Buffer.from('reply', 'utf8'),
    aAddress,
    bSess,
    bKeys
  );

  const errorMessage = SignalClient.DecryptionErrorMessage.forOriginal(
    bCiphertext.serialize(),
    bCiphertext.type(),
    45, // timestamp
    bAddress.deviceId()
  );
  const errorContent = SignalClient.PlaintextContent.from(errorMessage);
  const errorUSMC = SignalClient.UnidentifiedSenderMessageContent.new(
    SignalClient.CiphertextMessage.from(errorContent),
    senderCert,
    SignalClient.ContentHint.Implicit,
    null // group ID
  );
  const errorSealedSenderMessage = await SignalClient.sealedSenderEncrypt(
    errorUSMC,
    bAddress,
    aKeys
  );

  const bErrorUSMC = await SignalClient.sealedSenderDecryptToUsmc(
    errorSealedSenderMessage,
    bKeys
  );
  assert.equal(
    bErrorUSMC.msgType(),
    SignalClient.CiphertextMessageType.Plaintext
  );
  const bErrorContent = SignalClient.PlaintextContent.deserialize(
    bErrorUSMC.contents()
  );
  const bErrorMessage =
    SignalClient.DecryptionErrorMessage.extractFromSerializedBody(
      bErrorContent.body()
    );
  assert.equal(bErrorMessage.timestamp(), 45);
  assert.equal(bErrorMessage.deviceId(), bAddress.deviceId());

  const bSessionWithA = await bSess.getSession(aAddress);
  assert(
    bSessionWithA?.currentRatchetKeyMatches(
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      bErrorMessage.ratchetKey()!
    )
  );
});

it('SenderCertificate', () => {
  const trustRoot = SignalClient.PrivateKey.generate();
  const serverKey = SignalClient.PrivateKey.generate();

  const keyId = 23;

  const serverCert = SignalClient.ServerCertificate.new(
    keyId,
    serverKey.getPublicKey(),
    trustRoot
  );
  assert.deepEqual(serverCert.keyId(), keyId);
  assert.deepEqual(serverCert.key(), serverKey.getPublicKey());

  const serverCertFromBytes = SignalClient.ServerCertificate.deserialize(
    serverCert.serialize()
  );
  assert.deepEqual(serverCert, serverCertFromBytes);

  const senderUuid = 'fedfe51e-2b91-4156-8710-7cc1bdd57cd8';
  const senderE164 = '555-123-4567';
  const senderDeviceId = 9;
  const senderKey = SignalClient.PrivateKey.generate();
  const expiration = 2114398800; // Jan 1, 2037

  const senderCert = SignalClient.SenderCertificate.new(
    senderUuid,
    senderE164,
    senderDeviceId,
    senderKey.getPublicKey(),
    expiration,
    serverCert,
    serverKey
  );

  assert.deepEqual(senderCert.serverCertificate(), serverCert);
  assert.deepEqual(senderCert.senderUuid(), senderUuid);
  assert.deepEqual(senderCert.senderAci()?.getRawUuid(), senderUuid);
  assert.deepEqual(senderCert.senderE164(), senderE164);
  assert.deepEqual(senderCert.senderDeviceId(), senderDeviceId);

  const senderCertFromBytes = SignalClient.SenderCertificate.deserialize(
    senderCert.serialize()
  );
  assert.deepEqual(senderCert, senderCertFromBytes);

  assert(senderCert.validate(trustRoot.getPublicKey(), expiration - 1000));
  assert(!senderCert.validate(trustRoot.getPublicKey(), expiration + 10)); // expired

  const senderCertWithoutE164 = SignalClient.SenderCertificate.new(
    senderUuid,
    null,
    senderDeviceId,
    senderKey.getPublicKey(),
    expiration,
    serverCert,
    serverKey
  );

  assert.deepEqual(senderCertWithoutE164.serverCertificate(), serverCert);
  assert.deepEqual(senderCertWithoutE164.senderUuid(), senderUuid);
  assert.deepEqual(senderCertWithoutE164.senderAci()?.getRawUuid(), senderUuid);
  assert.isNull(senderCertWithoutE164.senderE164());
  assert.deepEqual(senderCertWithoutE164.senderDeviceId(), senderDeviceId);
});
it('SenderKeyMessage', () => {
  const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
  const chainId = 9;
  const iteration = 101;
  const ciphertext = Buffer.alloc(32, 0xfe);
  const pk = SignalClient.PrivateKey.generate();

  const skm = SignalClient.SenderKeyMessage._new(
    3,
    distributionId,
    chainId,
    iteration,
    ciphertext,
    pk
  );
  assert.deepEqual(skm.distributionId(), distributionId);
  assert.deepEqual(skm.chainId(), chainId);
  assert.deepEqual(skm.iteration(), iteration);
  assert.deepEqual(skm.ciphertext(), ciphertext);

  assert(skm.verifySignature(pk.getPublicKey()));

  const skmFromBytes = SignalClient.SenderKeyMessage.deserialize(
    skm.serialize()
  );
  assert.deepEqual(skm, skmFromBytes);
});
it('SenderKeyDistributionMessage', () => {
  const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
  const chainId = 9;
  const iteration = 101;
  const chainKey = Buffer.alloc(32, 0xfe);
  const pk = SignalClient.PrivateKey.generate();

  const skdm = SignalClient.SenderKeyDistributionMessage._new(
    3,
    distributionId,
    chainId,
    iteration,
    chainKey,
    pk.getPublicKey()
  );
  assert.deepEqual(skdm.distributionId(), distributionId);
  assert.deepEqual(skdm.chainId(), chainId);
  assert.deepEqual(skdm.iteration(), iteration);
  assert.deepEqual(skdm.chainKey(), chainKey);

  const skdmFromBytes = SignalClient.SenderKeyDistributionMessage.deserialize(
    skdm.serialize()
  );
  assert.deepEqual(skdm, skdmFromBytes);
});
describe('SenderKeyDistributionMessage Store API', () => {
  it('can encrypt and decrypt', async () => {
    const sender = SignalClient.ProtocolAddress.new('sender', 1);
    const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
    const aSenderKeyStore = new InMemorySenderKeyStore();
    const skdm = await SignalClient.SenderKeyDistributionMessage.create(
      sender,
      distributionId,
      aSenderKeyStore
    );
    assert.equal(distributionId, skdm.distributionId());
    assert.equal(0, skdm.iteration());

    const bSenderKeyStore = new InMemorySenderKeyStore();
    await SignalClient.processSenderKeyDistributionMessage(
      sender,
      skdm,
      bSenderKeyStore
    );

    const message = Buffer.from('0a0b0c', 'hex');

    const aCtext = await SignalClient.groupEncrypt(
      sender,
      distributionId,
      aSenderKeyStore,
      message
    );

    const bPtext = await SignalClient.groupDecrypt(
      sender,
      bSenderKeyStore,
      aCtext.serialize()
    );

    util.assertArrayEquals(message, bPtext);

    const anotherSkdm = await SignalClient.SenderKeyDistributionMessage.create(
      sender,
      distributionId,
      aSenderKeyStore
    );
    assert.equal(skdm.chainId(), anotherSkdm.chainId());
    assert.equal(1, anotherSkdm.iteration());
  });

  it("does not panic if there's an error", async () => {
    const sender = SignalClient.ProtocolAddress.new('sender', 1);
    const distributionId = 'd1d1d1d1-7000-11eb-b32a-33b8a8a487a6';
    const aSenderKeyStore = new InMemorySenderKeyStore();

    const messagePromise = SignalClient.SenderKeyDistributionMessage.create(
      sender,
      distributionId,
      undefined as unknown as SignalClient.SenderKeyStore
    );
    await assert.isRejected(messagePromise, TypeError);

    const messagePromise2 = SignalClient.SenderKeyDistributionMessage.create(
      {} as unknown as SignalClient.ProtocolAddress,
      distributionId,
      aSenderKeyStore
    );
    await assert.isRejected(messagePromise2, TypeError);
  });
});

it('PublicKeyBundle Kyber', () => {
  const signingKey = SignalClient.PrivateKey.generate();
  const registrationId = 5;
  const deviceId = 23;
  const prekeyId = 42;
  const prekey = SignalClient.PrivateKey.generate().getPublicKey();
  const signedPrekeyId = 2300;
  const signedPrekey = SignalClient.PrivateKey.generate().getPublicKey();
  const signedPrekeySignature = signingKey.sign(signedPrekey.serialize());
  const identityKey = SignalClient.PrivateKey.generate().getPublicKey();
  const kyberPrekeyId = 8888;
  const kyberPrekey = SignalClient.KEMKeyPair.generate().getPublicKey();
  const kyberPrekeySignature = signingKey.sign(kyberPrekey.serialize());

  const pkb = SignalClient.PreKeyBundle.new(
    registrationId,
    deviceId,
    prekeyId,
    prekey,
    signedPrekeyId,
    signedPrekey,
    signedPrekeySignature,
    identityKey,
    kyberPrekeyId,
    kyberPrekey,
    kyberPrekeySignature
  );

  assert.deepEqual(pkb.registrationId(), registrationId);
  assert.deepEqual(pkb.deviceId(), deviceId);
  assert.deepEqual(pkb.preKeyId(), prekeyId);
  assert.deepEqual(pkb.preKeyPublic(), prekey);
  assert.deepEqual(pkb.signedPreKeyId(), signedPrekeyId);
  assert.deepEqual(pkb.signedPreKeyPublic(), signedPrekey);
  assert.deepEqual(pkb.signedPreKeySignature(), signedPrekeySignature);
  assert.deepEqual(pkb.identityKey(), identityKey);
  assert.deepEqual(pkb.kyberPreKeyId(), kyberPrekeyId);
  assert.deepEqual(pkb.kyberPreKeyPublic(), kyberPrekey);
  assert.deepEqual(pkb.kyberPreKeySignature(), kyberPrekeySignature);

  // no one-time EC pre-key
  const pkb2 = SignalClient.PreKeyBundle.new(
    registrationId,
    deviceId,
    null,
    null,
    signedPrekeyId,
    signedPrekey,
    signedPrekeySignature,
    identityKey,
    kyberPrekeyId,
    kyberPrekey,
    kyberPrekeySignature
  );

  assert.deepEqual(pkb2.registrationId(), registrationId);
  assert.deepEqual(pkb2.deviceId(), deviceId);
  assert.deepEqual(pkb2.preKeyId(), null);
  assert.deepEqual(pkb2.preKeyPublic(), null);
  assert.deepEqual(pkb2.signedPreKeyId(), signedPrekeyId);
  assert.deepEqual(pkb2.signedPreKeyPublic(), signedPrekey);
  assert.deepEqual(pkb2.signedPreKeySignature(), signedPrekeySignature);
  assert.deepEqual(pkb2.identityKey(), identityKey);
  assert.deepEqual(pkb2.kyberPreKeyId(), kyberPrekeyId);
  assert.deepEqual(pkb2.kyberPreKeyPublic(), kyberPrekey);
  assert.deepEqual(pkb2.kyberPreKeySignature(), kyberPrekeySignature);
});

it('PreKeyRecord', () => {
  const privKey = SignalClient.PrivateKey.generate();
  const pubKey = privKey.getPublicKey();
  const pkr = SignalClient.PreKeyRecord.new(23, pubKey, privKey);

  assert.deepEqual(pkr.id(), 23);
  assert.deepEqual(pkr.publicKey(), pubKey);
  assert.deepEqual(pkr.privateKey(), privKey);

  const pkr2 = SignalClient.PreKeyRecord.deserialize(pkr.serialize());
  assert.deepEqual(pkr2.id(), 23);
  assert.deepEqual(pkr2.publicKey(), pubKey);
  assert.deepEqual(pkr2.privateKey(), privKey);
});
it('SignedPreKeyRecord', () => {
  const privKey = SignalClient.PrivateKey.generate();
  const pubKey = privKey.getPublicKey();
  const timestamp = 9000;
  const keyId = 23;
  const signature = Buffer.alloc(64, 64);
  const spkr = SignalClient.SignedPreKeyRecord.new(
    keyId,
    timestamp,
    pubKey,
    privKey,
    signature
  );

  assert.deepEqual(spkr.id(), keyId);
  assert.deepEqual(spkr.timestamp(), timestamp);
  assert.deepEqual(spkr.publicKey(), pubKey);
  assert.deepEqual(spkr.privateKey(), privKey);
  assert.deepEqual(spkr.signature(), signature);

  const spkrFromBytes = SignalClient.SignedPreKeyRecord.deserialize(
    spkr.serialize()
  );
  assert.deepEqual(spkrFromBytes, spkr);
});

it('KyberPreKeyRecord', () => {
  const keyPair = SignalClient.KEMKeyPair.generate();
  const publicKey = keyPair.getPublicKey();
  const secretKey = keyPair.getSecretKey();
  const timestamp = 9000;
  const keyId = 23;
  const signature = Buffer.alloc(64, 64);
  const record = SignalClient.KyberPreKeyRecord.new(
    keyId,
    timestamp,
    keyPair,
    signature
  );

  assert.deepEqual(record.id(), keyId);
  assert.deepEqual(record.timestamp(), timestamp);
  assert.deepEqual(record.keyPair(), keyPair);
  assert.deepEqual(record.publicKey(), publicKey);
  assert.deepEqual(record.secretKey(), secretKey);
  assert.deepEqual(record.signature(), signature);

  const recordFromBytes = SignalClient.KyberPreKeyRecord.deserialize(
    record.serialize()
  );
  assert.deepEqual(recordFromBytes, record);
});

it('SignalMessage and PreKeySignalMessage', () => {
  const messageVersion = 3;
  const macKey = Buffer.alloc(32, 0xab);
  const senderRatchetKey = SignalClient.PrivateKey.generate().getPublicKey();
  const counter = 9;
  const previousCounter = 8;
  const senderIdentityKey = SignalClient.PrivateKey.generate().getPublicKey();
  const receiverIdentityKey = SignalClient.PrivateKey.generate().getPublicKey();
  const ciphertext = Buffer.from('01020304', 'hex');

  const sm = SignalClient.SignalMessage._new(
    messageVersion,
    macKey,
    senderRatchetKey,
    counter,
    previousCounter,
    ciphertext,
    senderIdentityKey,
    receiverIdentityKey,
    Buffer.alloc(0)
  );

  assert.deepEqual(sm.counter(), counter);
  assert.deepEqual(sm.messageVersion(), messageVersion);

  const sm_bytes = sm.serialize();

  const sm2 = SignalClient.SignalMessage.deserialize(sm_bytes);

  assert.deepEqual(sm.body(), sm2.body());

  const registrationId = 9;
  const preKeyId = 23;
  const signedPreKeyId = 802;
  const baseKey = SignalClient.PrivateKey.generate().getPublicKey();
  const identityKey = SignalClient.PrivateKey.generate().getPublicKey();

  const pkm = SignalClient.PreKeySignalMessage._new(
    messageVersion,
    registrationId,
    preKeyId,
    signedPreKeyId,
    baseKey,
    identityKey,
    sm
  );
  assert.deepEqual(pkm.preKeyId(), preKeyId);
  assert.deepEqual(pkm.registrationId(), registrationId);
  assert.deepEqual(pkm.signedPreKeyId(), signedPreKeyId);
  assert.deepEqual(pkm.version(), messageVersion);

  const pkm_bytes = pkm.serialize();

  const pkm2 = SignalClient.PreKeySignalMessage.deserialize(pkm_bytes);

  assert.deepEqual(pkm2.serialize(), pkm_bytes);
});

const sessionVersionTestCases = [
  { suffix: 'v4', makeBundle: makePQXDHBundle, expectedVersion: 4 },
];

async function makePQXDHBundle(
  address: SignalClient.ProtocolAddress,
  stores: TestStores,
  excludeOneTimePreKey?: boolean
): Promise<SignalClient.PreKeyBundle> {
  const identityKey = await stores.identity.getIdentityKey();
  const prekeyId = chance.natural({ max: 10000 });
  const prekey = SignalClient.PrivateKey.generate();
  const signedPrekeyId = chance.natural({ max: 10000 });
  const signedPrekey = SignalClient.PrivateKey.generate();
  const signedPrekeySignature = identityKey.sign(
    signedPrekey.getPublicKey().serialize()
  );
  const kyberPrekeyId = chance.natural({ max: 10000 });
  const kyberKeyPair = SignalClient.KEMKeyPair.generate();
  const kyberPrekeySignature = identityKey.sign(
    kyberKeyPair.getPublicKey().serialize()
  );

  await stores.prekey.savePreKey(
    prekeyId,
    SignalClient.PreKeyRecord.new(prekeyId, prekey.getPublicKey(), prekey)
  );

  await stores.signed.saveSignedPreKey(
    signedPrekeyId,
    SignalClient.SignedPreKeyRecord.new(
      signedPrekeyId,
      chance.timestamp(),
      signedPrekey.getPublicKey(),
      signedPrekey,
      signedPrekeySignature
    )
  );

  await stores.kyber.saveKyberPreKey(
    kyberPrekeyId,
    SignalClient.KyberPreKeyRecord.new(
      kyberPrekeyId,
      chance.timestamp(),
      kyberKeyPair,
      kyberPrekeySignature
    )
  );

  return SignalClient.PreKeyBundle.new(
    await stores.identity.getLocalRegistrationId(),
    address.deviceId(),
    excludeOneTimePreKey ? null : prekeyId,
    excludeOneTimePreKey ? null : prekey.getPublicKey(),
    signedPrekeyId,
    signedPrekey.getPublicKey(),
    signedPrekeySignature,
    identityKey.getPublicKey(),
    kyberPrekeyId,
    kyberKeyPair.getPublicKey(),
    kyberPrekeySignature
  );
}

for (const testCase of sessionVersionTestCases) {
  describe(`Session ${testCase.suffix}`, () => {
    it('BasicPreKeyMessaging', async () => {
      const aliceStores = new TestStores();
      const bobStores = new TestStores();

      const aAddress = SignalClient.ProtocolAddress.new('+14151111111', 1);
      const bAddress = SignalClient.ProtocolAddress.new('+19192222222', 1);

      const bPreKeyBundle = await testCase.makeBundle(bAddress, bobStores);

      await SignalClient.processPreKeyBundle(
        bPreKeyBundle,
        bAddress,
        aliceStores.session,
        aliceStores.identity
      );
      const aMessage = Buffer.from('Greetings hoo-man', 'utf8');

      const aCiphertext = await SignalClient.signalEncrypt(
        aMessage,
        bAddress,
        aliceStores.session,
        aliceStores.identity
      );

      assert.deepEqual(
        aCiphertext.type(),
        SignalClient.CiphertextMessageType.PreKey
      );

      const aCiphertextR = SignalClient.PreKeySignalMessage.deserialize(
        aCiphertext.serialize()
      );

      const bDPlaintext = await SignalClient.signalDecryptPreKey(
        aCiphertextR,
        aAddress,
        bobStores.session,
        bobStores.identity,
        bobStores.prekey,
        bobStores.signed,
        bobStores.kyber
      );
      assert.deepEqual(bDPlaintext, aMessage);

      const bMessage = Buffer.from(
        'Sometimes the only thing more dangerous than a question is an answer.',
        'utf8'
      );

      const bCiphertext = await SignalClient.signalEncrypt(
        bMessage,
        aAddress,
        bobStores.session,
        bobStores.identity
      );

      assert.deepEqual(
        bCiphertext.type(),
        SignalClient.CiphertextMessageType.Whisper
      );

      const bCiphertextR = SignalClient.SignalMessage.deserialize(
        bCiphertext.serialize()
      );

      const aDPlaintext = await SignalClient.signalDecrypt(
        bCiphertextR,
        bAddress,
        aliceStores.session,
        aliceStores.identity
      );

      assert.deepEqual(aDPlaintext, bMessage);

      const session = await bobStores.session.getSession(aAddress);
      assert(session !== null);

      assert(session.serialize().length > 0);
      assert.deepEqual(session.localRegistrationId(), 5);
      assert.deepEqual(session.remoteRegistrationId(), 5);
      assert(session.hasCurrentState());
      assert(
        !session.currentRatchetKeyMatches(
          SignalClient.PrivateKey.generate().getPublicKey()
        )
      );

      session.archiveCurrentState();
      assert(!session.hasCurrentState());
      assert(
        !session.currentRatchetKeyMatches(
          SignalClient.PrivateKey.generate().getPublicKey()
        )
      );
    });

    it('handles duplicated messages', async () => {
      const aliceStores = new TestStores();
      const bobStores = new TestStores();

      const aAddress = SignalClient.ProtocolAddress.new('+14151111111', 1);
      const bAddress = SignalClient.ProtocolAddress.new('+19192222222', 1);

      const bPreKeyBundle = await testCase.makeBundle(bAddress, bobStores);

      await SignalClient.processPreKeyBundle(
        bPreKeyBundle,
        bAddress,
        aliceStores.session,
        aliceStores.identity
      );
      const aMessage = Buffer.from('Greetings hoo-man', 'utf8');

      const aCiphertext = await SignalClient.signalEncrypt(
        aMessage,
        bAddress,
        aliceStores.session,
        aliceStores.identity
      );

      assert.deepEqual(
        aCiphertext.type(),
        SignalClient.CiphertextMessageType.PreKey
      );

      const aCiphertextR = SignalClient.PreKeySignalMessage.deserialize(
        aCiphertext.serialize()
      );

      const bDPlaintext = await SignalClient.signalDecryptPreKey(
        aCiphertextR,
        aAddress,
        bobStores.session,
        bobStores.identity,
        bobStores.prekey,
        bobStores.signed,
        bobStores.kyber
      );
      assert.deepEqual(bDPlaintext, aMessage);

      try {
        await SignalClient.signalDecryptPreKey(
          aCiphertextR,
          aAddress,
          bobStores.session,
          bobStores.identity,
          bobStores.prekey,
          bobStores.signed,
          bobStores.kyber
        );
        assert.fail();
      } catch (e) {
        assert.instanceOf(e, Error);
        assert.instanceOf(e, SignalClient.LibSignalErrorBase);
        const err = e as SignalClient.LibSignalError;
        assert.equal(err.name, 'DuplicatedMessage');
        assert.equal(err.code, SignalClient.ErrorCode.DuplicatedMessage);
        assert.equal(err.operation, 'SessionCipher_DecryptPreKeySignalMessage'); // the Rust entry point
        assert.exists(err.stack); // Make sure we're still getting the benefits of Error.
      }

      const bMessage = Buffer.from(
        'Sometimes the only thing more dangerous than a question is an answer.',
        'utf8'
      );

      const bCiphertext = await SignalClient.signalEncrypt(
        bMessage,
        aAddress,
        bobStores.session,
        bobStores.identity
      );

      assert.deepEqual(
        bCiphertext.type(),
        SignalClient.CiphertextMessageType.Whisper
      );

      const bCiphertextR = SignalClient.SignalMessage.deserialize(
        bCiphertext.serialize()
      );

      const aDPlaintext = await SignalClient.signalDecrypt(
        bCiphertextR,
        bAddress,
        aliceStores.session,
        aliceStores.identity
      );

      assert.deepEqual(aDPlaintext, bMessage);

      try {
        await SignalClient.signalDecrypt(
          bCiphertextR,
          bAddress,
          aliceStores.session,
          aliceStores.identity
        );
        assert.fail();
      } catch (e) {
        assert.instanceOf(e, Error);
        assert.instanceOf(e, SignalClient.LibSignalErrorBase);
        const err = e as SignalClient.LibSignalError;
        assert.equal(err.name, 'DuplicatedMessage');
        assert.equal(err.code, SignalClient.ErrorCode.DuplicatedMessage);
        assert.equal(err.operation, 'SessionCipher_DecryptSignalMessage'); // the Rust entry point
        assert.exists(err.stack); // Make sure we're still getting the benefits of Error.
      }
    });

    it('expires unacknowledged sessions', async () => {
      const aliceStores = new TestStores();
      const bobStores = new TestStores();

      const bAddress = SignalClient.ProtocolAddress.new('+19192222222', 1);

      const bPreKeyBundle = await testCase.makeBundle(bAddress, bobStores);

      await SignalClient.processPreKeyBundle(
        bPreKeyBundle,
        bAddress,
        aliceStores.session,
        aliceStores.identity,
        new Date('2020-01-01')
      );

      const initialSession = await aliceStores.session.getSession(bAddress);
      assert.isTrue(initialSession?.hasCurrentState(new Date('2020-01-01')));
      assert.isFalse(initialSession?.hasCurrentState(new Date('2023-01-01')));

      const aMessage = Buffer.from('Greetings hoo-man', 'utf8');
      const aCiphertext = await SignalClient.signalEncrypt(
        aMessage,
        bAddress,
        aliceStores.session,
        aliceStores.identity,
        new Date('2020-01-01')
      );

      assert.deepEqual(
        aCiphertext.type(),
        SignalClient.CiphertextMessageType.PreKey
      );

      const updatedSession = await aliceStores.session.getSession(bAddress);
      assert.isTrue(updatedSession?.hasCurrentState(new Date('2020-01-01')));
      assert.isFalse(updatedSession?.hasCurrentState(new Date('2023-01-01')));

      await assert.isRejected(
        SignalClient.signalEncrypt(
          aMessage,
          bAddress,
          aliceStores.session,
          aliceStores.identity,
          new Date('2023-01-01')
        )
      );
    });

    it('rejects pre-key messages sent from a second user', async () => {
      const aliceStores = new TestStores();
      const bobStores = new TestStores();

      const aAddress = SignalClient.ProtocolAddress.new('+14151111111', 1);
      const bAddress = SignalClient.ProtocolAddress.new('+14151111112', 1);
      const mAddress = SignalClient.ProtocolAddress.new('+14151111113', 1);

      const bPreKeyBundle = await testCase.makeBundle(
        bAddress,
        bobStores,
        /*excludeOneTimePreKey*/ true
      );

      await SignalClient.processPreKeyBundle(
        bPreKeyBundle,
        bAddress,
        aliceStores.session,
        aliceStores.identity
      );
      const aMessage = Buffer.from('Greetings hoo-man', 'utf8');

      const aCiphertext = await SignalClient.signalEncrypt(
        aMessage,
        bAddress,
        aliceStores.session,
        aliceStores.identity
      );

      assert.deepEqual(
        aCiphertext.type(),
        SignalClient.CiphertextMessageType.PreKey
      );

      const aCiphertextR = SignalClient.PreKeySignalMessage.deserialize(
        aCiphertext.serialize()
      );

      void (await SignalClient.signalDecryptPreKey(
        aCiphertextR,
        aAddress,
        bobStores.session,
        bobStores.identity,
        bobStores.prekey,
        bobStores.signed,
        bobStores.kyber
      ));

      await assert.isRejected(
        SignalClient.signalDecryptPreKey(
          aCiphertextR,
          mAddress,
          bobStores.session,
          bobStores.identity,
          bobStores.prekey,
          bobStores.signed,
          bobStores.kyber
        )
      );
    });
  });
}

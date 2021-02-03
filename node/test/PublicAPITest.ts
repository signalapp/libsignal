//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import * as SignalClient from '../index';

SignalClient.initLogger(
  SignalClient.LogLevel.Trace,
  (level, target, fileOrNull, lineOrNull, message) => {
    const targetPrefix = target ? '[' + target + '] ' : '';
    const file = fileOrNull ?? '<unknown>';
    const line = lineOrNull ?? 0;
    // eslint-disable-next-line no-console
    console.log(targetPrefix + file + ':' + line + ': ' + message);
  }
);

describe('SignalClient', () => {
  it('HKDF test vector', () => {
    const hkdf = SignalClient.HKDF.new(3);

    const secret = Buffer.from(
      '0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B',
      'hex'
    );
    const empty = Buffer.from('', 'hex');

    assert.deepEqual(
      hkdf.deriveSecrets(42, secret, empty, empty).toString('hex'),
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
    );

    assert.deepEqual(
      hkdf.deriveSecrets(42, secret, empty, null).toString('hex'),
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
    );

    const salt = Buffer.from('000102030405060708090A0B0C', 'hex');
    const label = Buffer.from('F0F1F2F3F4F5F6F7F8F9', 'hex');

    assert.deepEqual(
      hkdf.deriveSecrets(42, secret, label, salt).toString('hex'),
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
    );
  });
  it('ProtocolAddress', () => {
    const addr = SignalClient.ProtocolAddress.new('name', 42);
    assert.deepEqual(addr.name(), 'name');
    assert.deepEqual(addr.deviceId(), 42);
  });
  it('PublicKeyBundle', () => {
    const registrationId = 5;
    const deviceId = 23;
    const prekeyId = 42;
    const prekey = SignalClient.PrivateKey.generate().getPublicKey();
    const signedPrekeyId = 2300;
    const signedPrekey = SignalClient.PrivateKey.generate().getPublicKey();
    const signedPrekeySignature = SignalClient.PrivateKey.generate().sign(
      Buffer.from('010203', 'hex')
    );
    const identityKey = SignalClient.PrivateKey.generate().getPublicKey();

    const pkb = SignalClient.PreKeyBundle.new(
      registrationId,
      deviceId,
      prekeyId,
      prekey,
      signedPrekeyId,
      signedPrekey,
      signedPrekeySignature,
      identityKey
    );

    assert.deepEqual(pkb.registrationId(), registrationId);
    assert.deepEqual(pkb.deviceId(), deviceId);
    assert.deepEqual(pkb.preKeyId(), prekeyId);
    assert.deepEqual(pkb.preKeyPublic(), prekey);
    assert.deepEqual(pkb.signedPreKeyId(), signedPrekeyId);
    assert.deepEqual(pkb.signedPreKeyPublic(), signedPrekey);
    assert.deepEqual(pkb.signedPreKeySignature(), signedPrekeySignature);
    assert.deepEqual(pkb.identityKey(), identityKey);

    // null handling:
    const pkb2 = SignalClient.PreKeyBundle.new(
      registrationId,
      deviceId,
      null,
      null,
      signedPrekeyId,
      signedPrekey,
      signedPrekeySignature,
      identityKey
    );

    assert.deepEqual(pkb2.registrationId(), registrationId);
    assert.deepEqual(pkb2.deviceId(), deviceId);
    assert.deepEqual(pkb2.preKeyId(), null);
    assert.deepEqual(pkb2.preKeyPublic(), null);
    assert.deepEqual(pkb2.signedPreKeyId(), signedPrekeyId);
    assert.deepEqual(pkb2.signedPreKeyPublic(), signedPrekey);
    assert.deepEqual(pkb2.signedPreKeySignature(), signedPrekeySignature);
    assert.deepEqual(pkb2.identityKey(), identityKey);
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
  it('SignalMessage and PreKeySignalMessage', () => {
    const messageVersion = 2;
    const macKey = Buffer.alloc(32, 0xab);
    const senderRatchetKey = SignalClient.PrivateKey.generate().getPublicKey();
    const counter = 9;
    const previousCounter = 8;
    const senderIdentityKey = SignalClient.PrivateKey.generate().getPublicKey();
    const receiverIdentityKey = SignalClient.PrivateKey.generate().getPublicKey();
    const ciphertext = Buffer.from('01020304', 'hex');

    const sm = SignalClient.SignalMessage.new(
      messageVersion,
      macKey,
      senderRatchetKey,
      counter,
      previousCounter,
      ciphertext,
      senderIdentityKey,
      receiverIdentityKey
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

    const pkm = SignalClient.PreKeySignalMessage.new(
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
  it('AES-GCM-SIV test vector', () => {
    // RFC 8452, appendix C.2
    const key = Buffer.from(
      '0100000000000000000000000000000000000000000000000000000000000000',
      'hex'
    );

    const aes_gcm_siv = SignalClient.Aes256GcmSiv.new(key);

    const nonce = Buffer.from('030000000000000000000000', 'hex');
    const aad = Buffer.from('010000000000000000000000', 'hex');
    const ptext = Buffer.from('02000000', 'hex');

    const ctext = aes_gcm_siv.encrypt(ptext, nonce, aad);

    assert.deepEqual(
      ctext.toString('hex'),
      '22b3f4cd1835e517741dfddccfa07fa4661b74cf'
    );

    const decrypted = aes_gcm_siv.decrypt(ctext, nonce, aad);

    assert.deepEqual(decrypted.toString('hex'), '02000000');
  });
  it('ECC signatures work', () => {
    const priv_a = SignalClient.PrivateKey.generate();
    const priv_b = SignalClient.PrivateKey.generate();
    assert.lengthOf(priv_a.serialize(), 32, 'private key serialization length');
    assert.deepEqual(priv_a.serialize(), priv_a.serialize(), 'repeatable');
    assert.notDeepEqual(
      priv_a.serialize(),
      priv_b.serialize(),
      'different for different keys'
    );

    const pub_a = priv_a.getPublicKey();
    const pub_b = priv_b.getPublicKey();

    const msg = Buffer.from([1, 2, 3]);

    const sig_a = priv_a.sign(msg);
    assert.lengthOf(sig_a, 64, 'signature length');

    assert(pub_a.verify(msg, sig_a));
    assert(!pub_b.verify(msg, sig_a));

    const sig_b = priv_b.sign(msg);
    assert.lengthOf(sig_b, 64, 'signature length');

    assert(pub_b.verify(msg, sig_b));
    assert(!pub_a.verify(msg, sig_b));
  });

  it('ECC key agreement work', () => {
    const priv_a = SignalClient.PrivateKey.generate();
    const priv_b = SignalClient.PrivateKey.generate();

    const pub_a = priv_a.getPublicKey();
    const pub_b = priv_b.getPublicKey();

    const shared_a = priv_a.agree(pub_b);
    const shared_b = priv_b.agree(pub_a);

    assert.deepEqual(shared_a, shared_b, 'key agreement works');
  });

  it('ECC keys roundtrip through serialization', () => {
    const key = Buffer.alloc(32, 0xab);
    const priv = SignalClient.PrivateKey.deserialize(key);
    assert(key.equals(priv.serialize()));

    const pub = priv.getPublicKey();
    const pub_bytes = pub.serialize();
    assert.lengthOf(pub_bytes, 32 + 1);

    const pub2 = SignalClient.PublicKey.deserialize(pub_bytes);

    assert.deepEqual(pub.serialize(), pub2.serialize());
  });

  it('decoding invalid ECC key throws an error', () => {
    const invalid_key = Buffer.alloc(33, 0xab);

    assert.throws(() => {
      SignalClient.PrivateKey.deserialize(invalid_key);
    }, 'bad key length <33> for key with type <Djb>');

    assert.throws(() => {
      SignalClient.PublicKey.deserialize(invalid_key);
    }, 'bad key type <0xab>');
  });
});

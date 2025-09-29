//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as SignalClient from '../index.js';
import * as util from './util.js';

import { assert, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Buffer } from 'node:buffer';

use(chaiAsPromised);
util.initLogger();

describe('SignalClient', () => {
  it('HKDF test vector', () => {
    const secret = Buffer.from(
      '0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B',
      'hex'
    );
    const empty = Buffer.from('', 'hex');

    util.assertByteArray(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
      SignalClient.hkdf(42, secret, empty, empty)
    );

    util.assertByteArray(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
      SignalClient.hkdf(42, secret, empty, null)
    );

    const salt = Buffer.from('000102030405060708090A0B0C', 'hex');
    const label = Buffer.from('F0F1F2F3F4F5F6F7F8F9', 'hex');

    util.assertByteArray(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
      SignalClient.hkdf(42, secret, label, salt)
    );
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

    util.assertByteArray('22b3f4cd1835e517741dfddccfa07fa4661b74cf', ctext);

    const decrypted = aes_gcm_siv.decrypt(ctext, nonce, aad);

    util.assertByteArray('02000000', decrypted);
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
    const key = Buffer.alloc(32, 0x40);
    const priv = SignalClient.PrivateKey.deserialize(key);
    assert(key.equals(priv.serialize()));

    const pub = priv.getPublicKey();
    const pub_bytes = pub.serialize();
    assert.lengthOf(pub_bytes, 32 + 1);

    const pub2 = SignalClient.PublicKey.deserialize(pub_bytes);

    assert.deepEqual(pub.serialize(), pub2.serialize());

    assert.deepEqual(pub.compare(pub2), 0);
    assert.deepEqual(pub2.compare(pub), 0);

    const anotherKey = SignalClient.PrivateKey.deserialize(
      Buffer.alloc(32, 0xcd)
    ).getPublicKey();
    assert.deepEqual(pub.compare(anotherKey), 1);
    assert.deepEqual(anotherKey.compare(pub), -1);

    assert.lengthOf(pub.getPublicKeyBytes(), 32);

    const keyPair = new SignalClient.IdentityKeyPair(pub, priv);
    const keyPairBytes = keyPair.serialize();
    const roundTripKeyPair =
      SignalClient.IdentityKeyPair.deserialize(keyPairBytes);
    assert.equal(roundTripKeyPair.publicKey.compare(pub), 0);
    const roundTripKeyPairBytes = roundTripKeyPair.serialize();
    assert.deepEqual(keyPairBytes, roundTripKeyPairBytes);
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

  it('can sign and verify alternate identity keys', () => {
    const primary = SignalClient.IdentityKeyPair.generate();
    const secondary = SignalClient.IdentityKeyPair.generate();
    const signature = secondary.signAlternateIdentity(primary.publicKey);
    assert(
      secondary.publicKey.verifyAlternateIdentity(primary.publicKey, signature)
    );
  });

  it('can do HPKE', () => {
    const keyPair = SignalClient.IdentityKeyPair.generate();
    const message = Uint8Array.of(11, 22, 33, 44);
    const sealed = keyPair.publicKey.seal(
      message,
      'test',
      Uint8Array.of(1, 2, 3)
    );
    const opened = keyPair.privateKey.open(
      sealed,
      'test',
      Uint8Array.of(1, 2, 3)
    );
    assert.deepEqual(opened, message);
  });

  it('includes all error codes in LibSignalError', () => {
    // This is a compilation test only.
    type MissingCodes = Exclude<
      SignalClient.ErrorCode,
      SignalClient.LibSignalError['code']
    >;
    function _check(
      hasMissingCode: MissingCodes extends never ? never : unknown
    ): MissingCodes {
      // If the following line errors with something like...
      //
      //     Type 'unknown' is not assignable to type 'ErrorCode.RateLimitedError | ErrorCode.BackupValidation'.
      //
      // ...that means `MissingCode extends never` was false, i.e. there were codes missing from the
      // LibSignalError union. Fortunately, the error message also tells you what they are.
      // (We ought to have been able to write this as `const missing: never = someMissingCodesValue`
      // or similar, but TypeScript 5.3 doesn't show the missing cases in the diagnostic that way.)
      return hasMissingCode;
    }
  });
});

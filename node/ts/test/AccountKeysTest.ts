//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import { Buffer } from 'node:buffer';

import * as AccountKeys from '../AccountKeys.js';
import * as util from './util.js';
import { Aci } from '../Address.js';
import { assertArrayNotEquals } from './util.js';
import * as uuid from '../uuid.js';

util.initLogger();

describe('AccountEntropyPool', () => {
  describe('generate()', () => {
    const NUM_TEST_ITERATIONS = 100;

    it('returns a unique string each time', () => {
      const generatedEntropyPools = new Set<string>();

      for (let i = 0; i < NUM_TEST_ITERATIONS; i++) {
        const pool = AccountKeys.AccountEntropyPool.generate();
        assert.isFalse(
          generatedEntropyPools.has(pool),
          `${pool} was generated twice`
        );
        generatedEntropyPools.add(pool);
      }
    });

    it('returns only strings consisting of 64 characters a-z and 0-9', () => {
      const validCharactersRegex = /^[a-z0-9]{64}$/;
      for (let i = 0; i < NUM_TEST_ITERATIONS; i++) {
        const pool = AccountKeys.AccountEntropyPool.generate();
        assert.match(
          pool,
          validCharactersRegex,
          'Pool must be 64 characters consisting of only a-z and 0-9'
        );
      }
    });
  });

  it('can derive SVR keys', () => {
    const pool = AccountKeys.AccountEntropyPool.generate();
    const svrKey = AccountKeys.AccountEntropyPool.deriveSvrKey(pool);
    assert.equal(32, svrKey.length);
  });
});

describe('BackupKey', () => {
  const aci = Aci.fromUuidBytes(new Uint8Array(16).fill(0x11));

  it('can be derived or randomly generated', () => {
    const pool = AccountKeys.AccountEntropyPool.generate();
    const backupKey = AccountKeys.AccountEntropyPool.deriveBackupKey(pool);
    assert.equal(32, backupKey.serialize().length);

    const randomKey = AccountKeys.BackupKey.generateRandom();
    assertArrayNotEquals(backupKey.serialize(), randomKey.serialize());
  });

  it('can generate derived keys', () => {
    const pool = AccountKeys.AccountEntropyPool.generate();
    const backupKey = AccountKeys.AccountEntropyPool.deriveBackupKey(pool);
    const randomKey = AccountKeys.BackupKey.generateRandom();
    const otherAci = Aci.fromUuidBytes(uuid.v4());

    const backupId = backupKey.deriveBackupId(aci);
    assert.equal(16, backupId.length);
    assertArrayNotEquals(backupId, randomKey.deriveBackupId(aci));
    assertArrayNotEquals(backupId, backupKey.deriveBackupId(otherAci));

    const ecKey = backupKey.deriveEcKey(aci);
    assertArrayNotEquals(
      ecKey.serialize(),
      randomKey.deriveEcKey(aci).serialize()
    );
    assertArrayNotEquals(
      ecKey.serialize(),
      backupKey.deriveEcKey(otherAci).serialize()
    );

    const localMetadataKey = backupKey.deriveLocalBackupMetadataKey();
    assert.equal(32, localMetadataKey.length);

    const mediaId = backupKey.deriveMediaId('example.jpg');
    assert.equal(15, mediaId.length);

    const mediaKey = backupKey.deriveMediaEncryptionKey(mediaId);
    assert.equal(32 + 32, mediaKey.length);

    assert.throws(() => backupKey.deriveMediaEncryptionKey(Buffer.of(0)));

    // This media ID wasn't for a thumbnail, but the API doesn't (can't) check that.
    const thumbnailKey = backupKey.deriveThumbnailTransitEncryptionKey(mediaId);
    assert.equal(32 + 32, mediaKey.length);
    assertArrayNotEquals(mediaKey, thumbnailKey);
  });
});

describe('PinHash', () => {
  const testPin = Buffer.from('password', 'utf-8');
  const testSalt = Buffer.from(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'hex'
  );

  it('fromSalt produces 32-byte encryptionKey and accessKey', () => {
    const ph = AccountKeys.PinHash.fromSalt(testPin, testSalt);
    assert.equal(ph.encryptionKey.length, 32);
    assert.equal(ph.accessKey.length, 32);
  });

  it('fromSalt is deterministic', () => {
    const ph1 = AccountKeys.PinHash.fromSalt(testPin, testSalt);
    const ph2 = AccountKeys.PinHash.fromSalt(testPin, testSalt);
    assert.deepEqual(ph1.encryptionKey, ph2.encryptionKey);
    assert.deepEqual(ph1.accessKey, ph2.accessKey);
  });

  it('different salts produce different keys', () => {
    const ph1 = AccountKeys.PinHash.fromSalt(testPin, testSalt);
    const ph2 = AccountKeys.PinHash.fromSalt(
      testPin,
      Buffer.from(
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
        'hex'
      )
    );
    assertArrayNotEquals(ph1.encryptionKey, ph2.encryptionKey);
  });

  it('encryptionKey and accessKey are different', () => {
    const ph = AccountKeys.PinHash.fromSalt(testPin, testSalt);
    assertArrayNotEquals(ph.encryptionKey, ph.accessKey);
  });

  it('fromSalt rejects a salt that is not 32 bytes', () => {
    assert.throws(() => AccountKeys.PinHash.fromSalt(testPin, Buffer.of(0xff)));
  });

  it('fromSalt produces known accessKey', () => {
    const ph = AccountKeys.PinHash.fromSalt(testPin, testSalt);
    assert.deepEqual(
      Buffer.from(ph.accessKey).toString('hex'),
      'ab7e8499d21f80a6600b3b9ee349ac6d72c07e3359fe885a934ba7aa844429f8'
    );
  });

  it('fromSalt produces known encryptionKey', () => {
    const ph = AccountKeys.PinHash.fromSalt(testPin, testSalt);
    assert.deepEqual(
      Buffer.from(ph.encryptionKey).toString('hex'),
      '44652df80490fc66bb864a9e638b2f7dc9e20649671dd66bbb9c37bee2bfecf1'
    );
  });

  it('fromSalt produces known keys for a second vector', () => {
    const pin2 = Buffer.from('anotherpassword', 'utf-8');
    const salt2 = Buffer.from(
      '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
      'hex'
    );
    const ph = AccountKeys.PinHash.fromSalt(pin2, salt2);
    assert.deepEqual(
      Buffer.from(ph.accessKey).toString('hex'),
      '301d9dd1e96f20ce51083f67d3298fd37b97525de8324d5e12ed2d407d3d927b'
    );
    assert.deepEqual(
      Buffer.from(ph.encryptionKey).toString('hex'),
      'b6f16aa0591732e339b7e99cdd5fd6586a1c285c9d66876947fd82f66ed99757'
    );
  });

  it('fromUsernameMrenclave produces the same keys as fromSalt with the derived salt', () => {
    const mrenclave = Buffer.from(
      '97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535',
      'hex'
    );
    const knownSalt = Buffer.from(
      '70dd66bdcbb23f5173323f054becc5b617ae475ba8de067946f198efff7a5f83',
      'hex'
    );
    const actual = AccountKeys.PinHash.fromUsernameMrenclave(
      testPin,
      'username',
      mrenclave
    );
    const expected = AccountKeys.PinHash.fromSalt(testPin, knownSalt);
    assert.deepEqual(actual.accessKey, expected.accessKey);
    assert.deepEqual(actual.encryptionKey, expected.encryptionKey);
  });
});

describe('Pin', () => {
  const testPin = Buffer.from('password', 'utf-8');

  it('localHash produces a non-empty string', () => {
    const hash = AccountKeys.Pin.localHash(testPin);
    assert.isString(hash);
    assert.isAbove(hash.length, 0);
  });

  it('verifyLocalHash returns true for correct pin', () => {
    const hash = AccountKeys.Pin.localHash(testPin);
    assert.isTrue(AccountKeys.Pin.verifyLocalHash(hash, testPin));
  });

  it('verifyLocalHash returns false for wrong pin', () => {
    const hash = AccountKeys.Pin.localHash(testPin);
    assert.isFalse(
      AccountKeys.Pin.verifyLocalHash(hash, Buffer.from('badpassword', 'utf-8'))
    );
  });

  it('verifyLocalHash throws on a malformed hash', () => {
    assert.throws(() =>
      AccountKeys.Pin.verifyLocalHash(
        'not-a-hash',
        Buffer.from('password', 'utf-8')
      )
    );
  });
});

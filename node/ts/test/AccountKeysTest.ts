//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import * as uuid from 'uuid';
import * as AccountKeys from '../AccountKeys';
import * as util from './util';
import { Aci } from '../Address';

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
    assert.notEqual(
      backupKey.serialize().toString('hex'),
      randomKey.serialize().toString('hex')
    );
  });

  it('can generate derived keys', () => {
    const pool = AccountKeys.AccountEntropyPool.generate();
    const backupKey = AccountKeys.AccountEntropyPool.deriveBackupKey(pool);
    const randomKey = AccountKeys.BackupKey.generateRandom();
    const otherAci = Aci.fromUuid(uuid.v4());

    const backupId = backupKey.deriveBackupId(aci);
    assert.equal(16, backupId.length);
    assert.notEqual(
      backupId.toString('hex'),
      randomKey.deriveBackupId(aci).toString('hex')
    );
    assert.notEqual(
      backupId.toString('hex'),
      backupKey.deriveBackupId(otherAci).toString('hex')
    );

    const ecKey = backupKey.deriveEcKey(aci);
    assert.notEqual(
      ecKey.serialize().toString('hex'),
      randomKey.deriveEcKey(aci).serialize().toString('hex')
    );
    assert.notEqual(
      ecKey.serialize().toString('hex'),
      backupKey.deriveEcKey(otherAci).serialize().toString('hex')
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
    assert.notEqual(mediaKey.toString('hex'), thumbnailKey.toString('hex'));
  });
});

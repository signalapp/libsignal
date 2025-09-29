//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import * as uuid from 'uuid';
import { Buffer } from 'node:buffer';

import * as AccountKeys from '../AccountKeys.js';
import * as util from './util.js';
import { Aci } from '../Address.js';
import { assertArrayNotEquals } from './util.js';

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
    const otherAci = Aci.fromUuid(uuid.v4());

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

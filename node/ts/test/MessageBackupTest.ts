//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import * as MessageBackup from '../MessageBackup';
import * as util from './util';
import { Aci } from '../Address';
import { Uint8ArrayInputStream, ErrorInputStream } from './ioutil';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { hkdf, LogLevel } from '..';
import { BackupKey } from '../AccountKeys';

util.initLogger(LogLevel.Trace);

describe('MessageBackup', () => {
  const accountEntropy = 'm'.repeat(64);
  const aci = Aci.fromUuidBytes(new Uint8Array(16).fill(0x11));
  const testKey = new MessageBackup.MessageBackupKey({ accountEntropy, aci });
  const purpose = MessageBackup.Purpose.RemoteBackup;

  describe('validate', () => {
    it('successfully validates a minimal backup', async () => {
      const input = fs.readFileSync(
        path.join(__dirname, '../../ts/test/new_account.binproto.encrypted')
      );

      const outcome = await MessageBackup.validate(
        testKey,
        purpose,
        () => new Uint8ArrayInputStream(input),
        BigInt(input.length)
      );
      assert.equal(outcome.errorMessage, null);

      // If we manually derive the test key's backup key and ID, we should get the same outcome.
      const backupKey = hkdf(
        32,
        Buffer.from(accountEntropy, 'utf8'),
        Buffer.from('20240801_SIGNAL_BACKUP_KEY', 'utf8'),
        null
      );
      const backupId = hkdf(
        16,
        backupKey,
        Buffer.concat([
          Buffer.from('20241024_SIGNAL_BACKUP_ID:', 'utf8'),
          aci.getServiceIdBinary(),
        ]),
        null
      );
      const testKeyFromBackupId = new MessageBackup.MessageBackupKey({
        backupKey: new BackupKey(backupKey),
        backupId,
      });

      const outcome2 = await MessageBackup.validate(
        testKeyFromBackupId,
        purpose,
        () => new Uint8ArrayInputStream(input),
        BigInt(input.length)
      );
      assert.equal(outcome2.errorMessage, null);
    });

    it('provides its HMAC and AES keys', () => {
      // Just check some basic expectations.
      assert.equal(32, testKey.hmacKey.length);
      assert.equal(32, testKey.aesKey.length);
      assert.isFalse(testKey.hmacKey.equals(testKey.aesKey));
    });

    it('produces an error message on empty input', async () => {
      const outcome = await MessageBackup.validate(
        testKey,
        purpose,
        () => new Uint8ArrayInputStream(new Uint8Array()),
        0n
      );
      assert.equal(outcome.errorMessage, 'not enough bytes for an HMAC');
    });

    it('throws a raised IO error', async () => {
      try {
        await MessageBackup.validate(
          testKey,
          purpose,
          () => new ErrorInputStream(),
          234n
        );
        assert.fail('did not throw');
      } catch (e) {
        assert.instanceOf(e, ErrorInputStream.Error);
      }
    });
  });
});

describe('ComparableBackup', () => {
  describe('exampleBackup', () => {
    const input = fs.readFileSync(
      path.join(__dirname, '../../ts/test/canonical-backup.binproto')
    );

    it('stringifies to the expected value', async () => {
      const comparable = await MessageBackup.ComparableBackup.fromUnencrypted(
        MessageBackup.Purpose.RemoteBackup,
        new Uint8ArrayInputStream(input),
        BigInt(input.length)
      );

      const expectedOutput = fs.readFileSync(
        path.join(__dirname, '../../ts/test/canonical-backup.expected.json')
      );
      const output = comparable.comparableString();
      assert.equal(output, new String(expectedOutput));
    });
  });
});

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
import { LogLevel } from '..';

util.initLogger(LogLevel.Trace);

describe('MessageBackup', () => {
  const masterKey = Buffer.from(new Uint8Array(32).fill('M'.charCodeAt(0)));
  const aci = Aci.fromUuidBytes(new Uint8Array(16).fill(0x11));
  const testKey = new MessageBackup.MessageBackupKey(masterKey, aci);
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

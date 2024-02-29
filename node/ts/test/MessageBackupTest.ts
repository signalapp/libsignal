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

  describe('validate', () => {
    it('successfully validates a minimal backup', async () => {
      const input = fs.readFileSync(
        path.join(__dirname, '../../ts/test/new_account.binproto.encrypted')
      );

      const outcome = await MessageBackup.validate(
        testKey,
        () => new Uint8ArrayInputStream(input),
        BigInt(input.length)
      );
      assert.equal(outcome.errorMessage, null);
    });

    it('produces an error message on empty input', async () => {
      const outcome = await MessageBackup.validate(
        testKey,
        () => new Uint8ArrayInputStream(new Uint8Array()),
        0n
      );
      assert.equal(outcome.errorMessage, 'not enough bytes for an HMAC');
    });

    it('throws a raised IO error', async () => {
      try {
        await MessageBackup.validate(
          testKey,
          () => new ErrorInputStream(),
          BigInt(234)
        );
        assert.fail('did not throw');
      } catch (e) {
        assert.instanceOf(e, ErrorInputStream.Error);
      }
    });
  });
});

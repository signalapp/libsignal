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
import { AccountEntropyPool, BackupKey } from '../AccountKeys';
import { Readable } from 'node:stream';

util.initLogger(LogLevel.Trace);

describe('AccountEntropyPool', () => {
  describe('isValid', () => {
    assert.isFalse(AccountEntropyPool.isValid('invalid key'));
    assert.isTrue(
      AccountEntropyPool.isValid(
        '0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr'
      )
    );
  });
});

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

const exampleBackup = fs.readFileSync(
  path.join(__dirname, '../../ts/test/canonical-backup.binproto')
);

describe('ComparableBackup', () => {
  describe('exampleBackup', () => {
    it('stringifies to the expected value', async () => {
      const comparable = await MessageBackup.ComparableBackup.fromUnencrypted(
        MessageBackup.Purpose.RemoteBackup,
        new Uint8ArrayInputStream(exampleBackup),
        BigInt(exampleBackup.length)
      );

      const expectedOutput = fs.readFileSync(
        path.join(__dirname, '../../ts/test/canonical-backup.expected.json')
      );
      const output = comparable.comparableString();
      assert.equal(output, new String(expectedOutput));
    });
  });
});

describe('OnlineBackupValidator', () => {
  it('can read frames from a valid file', () => {
    // `Readable.read` normally returns `any`, because it supports settable encodings.
    // Here we override that `read` member with one that always produces a Buffer,
    // for more convenient use in the test. Note that this is unchecked.
    type ReadableUsingBuffer = Omit<Readable, 'read'> & {
      read(size: number): Buffer;
    };
    const input: ReadableUsingBuffer = new Readable();
    input.push(exampleBackup);
    input.push(null);

    const backupInfoLength = input.read(1)[0];
    assert.isBelow(backupInfoLength, 0x80, 'single-byte varint');
    const backupInfo = input.read(backupInfoLength);
    assert.equal(backupInfo.length, backupInfoLength, 'unexpected EOF');
    const backup = new MessageBackup.OnlineBackupValidator(
      backupInfo,
      MessageBackup.Purpose.RemoteBackup
    );

    let frameLengthBuf;
    while ((frameLengthBuf = input.read(1))) {
      let frameLength = frameLengthBuf[0];
      // Tiny varint parser, only supports two bytes.
      if (frameLength >= 0x80) {
        const secondByte = input.read(1)[0];
        assert.isBelow(secondByte, 0x80, 'at most a two-byte varint');
        frameLength -= 0x80;
        frameLength |= secondByte << 7;
      }
      const frame = input.read(frameLength);
      assert.equal(frame.length, frameLength, 'unexpected EOF');
      backup.addFrame(frame);
    }

    backup.finalize();
  });

  it('rejects invalid BackupInfo', () => {
    assert.throws(
      () =>
        new MessageBackup.OnlineBackupValidator(
          Buffer.of(),
          MessageBackup.Purpose.RemoteBackup
        )
    );
  });

  // The following payload was generated via protoscope.
  // % protoscope -s | base64
  // The fields are described by Backup.proto.
  //
  // 1: 1
  // 2: 1731715200000
  // 3: {`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`}
  const VALID_BACKUP_INFO: Buffer = Buffer.from(
    'CAEQgOiTkrMyGiAAESIzRFVmd4iZqrvM3e7/ABEiM0RVZneImaq7zN3u/w==',
    'base64'
  );

  it('rejects invalid Frames', () => {
    const backup = new MessageBackup.OnlineBackupValidator(
      VALID_BACKUP_INFO,
      MessageBackup.Purpose.RemoteBackup
    );
    assert.throws(() => backup.addFrame(Buffer.of()));
  });

  it('rejects invalid backups on finalize', () => {
    const backup = new MessageBackup.OnlineBackupValidator(
      VALID_BACKUP_INFO,
      MessageBackup.Purpose.RemoteBackup
    );
    assert.throws(() => backup.finalize());
  });
});

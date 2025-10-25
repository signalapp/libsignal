//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import { Buffer } from 'node:buffer';

import { Environment, Net, SvrB } from '../net.js';
import { BackupKey, BackupForwardSecrecyToken } from '../AccountKeys.js';
import { Aci } from '../Address.js';
import * as Native from '../Native.js';

describe('SecureValueRecoveryBackup', () => {
  const testAci = Aci.parseFromServiceIdString(
    'e74beed0-e70f-4cfd-abbb-7e3eb333bbac'
  );
  const testBackupKey = BackupKey.generateRandom();
  const testBackupIdString = Buffer.from(
    testBackupKey.deriveBackupId(testAci)
  ).toString('hex');
  const testInvalidSecretData = new Uint8Array([1, 2, 3, 4]);
  const enclaveSecret = process.env.LIBSIGNAL_TESTING_SVRB_ENCLAVE_SECRET;
  const testAuth = enclaveSecret
    ? {
        username: testBackupIdString,
        password: Native.TESTING_CreateOTPFromBase64(
          testBackupIdString,
          enclaveSecret
        ),
      }
    : {
        username: process.env.LIBSIGNAL_TESTING_SVRB_USERNAME || '',
        password: process.env.LIBSIGNAL_TESTING_SVRB_PASSWORD || '',
      };

  let net: Net;
  let svrB: SvrB;

  beforeEach(() => {
    net = new Net({ env: Environment.Staging, userAgent: 'test' });
    svrB = net.svrB(testAuth);
  });

  describe('storeBackup', () => {
    it('throws error with invalid previous secret data', async () => {
      // Invalid protobuf data should cause an error
      const invalidSecretData = new Uint8Array([0xff, 0xff, 0xff, 0xff]);

      return assert.isRejected(
        svrB.store(testBackupKey, invalidSecretData),
        Error,
        'Invalid data from previous backup'
      );
    });

    it('throws error with arbitrary test secret data', async () => {
      // Arbitrary test secret data should cause an error
      return assert.isRejected(
        svrB.store(testBackupKey, testInvalidSecretData),
        Error,
        'Invalid data from previous backup'
      );
    });
  });

  describe('restoreBackup', () => {
    it('returns a promise', () => {
      const result = svrB.restore(testBackupKey, new Uint8Array());
      assert.instanceOf(result, Promise);
      // eslint-disable-next-line promise/prefer-await-to-then
      result.catch(() => {});
    });

    it('supports abort signal', () => {
      const abortController = new AbortController();
      const result = svrB.restore(testBackupKey, new Uint8Array(), {
        abortSignal: abortController.signal,
      });
      assert.instanceOf(result, Promise);
      // eslint-disable-next-line promise/prefer-await-to-then
      result.catch(() => {});
    });
  });

  describe('Integration test with network calls', () => {
    beforeEach(function () {
      if (
        !process.env.LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS ||
        testAuth.username == '' ||
        testAuth.password == ''
      ) {
        this.skip();
      }
    });
    afterEach(async function () {
      if (this.currentTest && !this.currentTest.isPending()) {
        try {
          await svrB.remove();
        } catch (e) {
          // eslint-disable-next-line no-console
          console.log(e);
        }
      }
    });

    it('completes full backup and restore flow with previous secret data', async () => {
      // First backup without previous data
      const initialSecretData = svrB.createNewBackupChain(testBackupKey);
      const firstResponse = await svrB.store(testBackupKey, initialSecretData);
      assert.exists(firstResponse);
      const {
        nextBackupSecretData: firstNextSecretData,
        metadata: firstMetadata,
        forwardSecrecyToken: firstToken,
      } = firstResponse;

      assert.exists(firstNextSecretData);
      assert.instanceOf(firstNextSecretData, Uint8Array);
      assert.isNotEmpty(firstNextSecretData);

      const restoredFirst = await svrB.restore(testBackupKey, firstMetadata);

      assert.deepEqual(
        firstToken.serialize(),
        restoredFirst.forwardSecrecyToken.serialize()
      );

      // Second backup with previous secret data
      const secondResponse = await svrB.store(
        testBackupKey,
        firstNextSecretData
      );

      const secondToken = secondResponse.forwardSecrecyToken;
      assert.exists(secondToken);
      assert.instanceOf(secondToken, BackupForwardSecrecyToken);

      // Should also have next secret data for future backups
      assert.isNotEmpty(secondResponse.nextBackupSecretData);

      const restoredSecond = await svrB.restore(
        testBackupKey,
        secondResponse.metadata
      );

      assert.deepEqual(
        secondToken.serialize(),
        restoredSecond.forwardSecrecyToken.serialize()
      );

      // The tokens should be different between backups
      assert.notDeepEqual(firstToken.serialize(), secondToken.serialize());
    }).timeout(10000);
  });
});

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as Native from '../../Native.js';
import * as util from '../util.js';
import { TokioAsyncContext, UnauthBackupsService } from '../../net.js';
import { connectUnauth, testSimpleGrpcRequest } from './ServiceTestUtils.js';
import {
  BackupAuthCredential,
  GenericServerPublicParams,
} from '../../zkgroup/index.js';
import { PrivateKey } from '../../EcKeys.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';
import { fromBase64, toBase64 } from '../util.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthBackupsService', () => {
  // These constants are from api/backups.rs
  const TEST_CREDENTIAL = fromBase64(
    'AACkl2kAAAAAyQAAAAAAAAACAAAAAAAAAMUH8mZNP0qDpXFbK2e3dKL04Zw1UhyJ5ab+RlRLhAYELu5/fvwOhxzvxcnNGpqppkGOWc7SSN0kEU0MMIslejR+FDPRx0BWeRTeMmr2ngFVaHUjmazUmgCAPkr0BuLjShTidN9UW8r2M6FjodEtF/8='
  );
  const TEST_SERVER_KEYS = fromBase64(
    'AIRCHmMrkZXZ9ZuwKJkA0GeMOaDSdVsU26AghADhY3l5XBYwf0UCtm2tvvYsbnPgh9uIUyERm0Wg3v7pFtg+OEfsM6fwjdBFqAgfeqs1pT9nwp2Wp6oGdAfCTrGcqraXJoyAiwAh3vogu7ltucNKh25zKiOkIeIEJNrjbx2eEwkFnqLYuk/noxaOi2Zl7R5d7+vn0Me0d2AZhu0Uuk1vpTIuYf+X4UJXV/N5TYYxwOe/OQHu4zZmdaPjtPN1EHFJC5ALV+8BY9dN5ddS7iTL1uq1ksURAA9hAZzC9/aTr7J7'
  );
  const TEST_SIGNING_KEY = fromBase64(
    'KMhdmPEusAwoT3C2LzIbmGX6z+3HMbhgbrXmUwRfGF0='
  );
  const TEST_SIGNING_KEY_PUB = fromBase64(
    'BWp7eOx6q6IlijMPozln1bY34JoLFZhGu3PLDnn7hO9t'
  );
  const EXPECTED_PRESENTATION = fromBase64(
    'AMkAAAAAAAAAAgAAAAAAAAAApJdpAAAAAIoiVNK2DtZIRFCtQxRiSokkSiQEKrUm86QgMg+qyZZjLuJipcWuggZt6au2i4MOhslTP4qafDZUYWZnKdX7zV4MKW1+FqHVi9kns3+gGaHRCrUEqKcTBzZj/C79ZRJObwIAAAAAAAAA7vpvGr5uokinX1GRCgDr5au1ajuE2naAsAUXPXXpxTyKZo+S3m3OdyDUusIM3sIyUFwM1OeMtmHLgDcuGAqKdYAAAAAAAAAAcqkJSxGNgTB4ERB7Qcg8tp+IZnEhGxCzuvY3KqrjgwA1LniEMcZCO9kjcSL2Q5JS5yZYrv7Kkn0p3hY4vIrKBlgb0zycYLKRrUj+ndkHKJtWV/2xC42jehDUc1P2ufIEJfu4ScD+sUt9fgAV7uDsKI/ktXnhUPT7/ZxtCCp88gEU4nTfVFvK9jOhY6HRLRf/'
  );
  const EXPECTED_SIGNATURE = fromBase64(
    'TUmhLTMN7LLUOphZiAF8WZekmWzYDWlDiqNm3LirWwcSotw+yUd+MOizCpwVD+Wp9dLHjqU00xUwm+KnxtiKiA=='
  );
  const TEST_AUTH = {
    credential: new BackupAuthCredential(TEST_CREDENTIAL),
    serverKeys: new GenericServerPublicParams(TEST_SERVER_KEYS),
    signingKey: PrivateKey.deserialize(TEST_SIGNING_KEY),
  };
  for (const [name, endpoint] of [
    ['getUploadForm', '/v1/archives/upload/form'] as const,
    ['getMediaUploadForm', '/v1/archives/media/upload/form'] as const,
  ]) {
    describe(name, () => {
      it('returns different values if RNG is not provided', async () => {
        const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
        const [chat, fakeRemote] = connectUnauth<UnauthBackupsService>(tokio);
        const _ignoredFuture1 = chat[name]({
          auth: TEST_AUTH,
          uploadSize: 12345,
        });
        const request1 = await fakeRemote.assertReceiveIncomingRequest();
        const _ignoredFuture2 = chat[name]({
          auth: TEST_AUTH,
          uploadSize: 12345,
        });
        const request2 = await fakeRemote.assertReceiveIncomingRequest();
        expect(request1.headers.get('x-signal-zk-auth')).to.not.eq(
          request2.headers.get('x-signal-zk-auth')
        );
        fakeRemote.sendReplyTo(request1, { status: 500 });
        fakeRemote.sendReplyTo(request2, { status: 500 });
      });
      it('should property return an upload form', async () => {
        const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
        const [chat, fakeRemote] = connectUnauth<UnauthBackupsService>(tokio);
        Native.TESTING_EnableDeterministicRngForTesting();
        const responseFuture = chat[name]({
          auth: TEST_AUTH,
          uploadSize: 12345,
          rng: {
            __deterministicRngSeedForTesting: 0,
          },
        });
        const request = await fakeRemote.assertReceiveIncomingRequest();
        expect(request.verb).to.equal('GET');
        expect(request.path).to.equal(`${endpoint}?uploadLength=12345`);
        expect(request.headers).to.deep.equal(
          new Map([
            ['x-signal-zk-auth', toBase64(EXPECTED_PRESENTATION)],
            ['x-signal-zk-auth-signature', toBase64(EXPECTED_SIGNATURE)],
          ])
        );
        fakeRemote.sendReplyTo(request, {
          status: 200,
          message: 'OK',
          headers: ['content-type: application/json'],
          body: new TextEncoder().encode(
            JSON.stringify({
              cdn: 123,
              key: 'abcde',
              headers: { one: 'val1', two: 'val2' },
              signedUploadLocation: 'http://example.org/upload',
            })
          ),
        });
        const uploadForm = await responseFuture;
        expect(uploadForm.cdn).to.equal(123);
        expect(uploadForm.key).to.equal('abcde');
        expect(uploadForm.headers).to.deep.equal(
          new Map([
            ['one', 'val1'],
            ['two', 'val2'],
          ])
        );
        expect(uploadForm.signedUploadUrl).to.deep.eq(
          new URL('http://example.org/upload')
        );
      });
      it('should correctly throw errors', async () => {
        for (const [status, code] of [
          [403, ErrorCode.RequestUnauthorized],
          [413, ErrorCode.UploadTooLarge],
        ]) {
          const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
          const [chat, fakeRemote] = connectUnauth<UnauthBackupsService>(tokio);
          const responseFuture = chat[name]({
            auth: TEST_AUTH,
            uploadSize: 12345,
          });
          const request = await fakeRemote.assertReceiveIncomingRequest();
          fakeRemote.sendReplyTo(request, { status });
          await expect(responseFuture)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code,
            });
        }
      });
    });
  }

  async function testSimpleBackupRequestUnauthorized<T>(
    requestName: string,
    expectedRequest: Record<string, unknown>,
    responseName: string,
    sendRequest: (chat: UnauthBackupsService) => Promise<T>
  ) {
    const responseFuture = testSimpleGrpcRequest(
      requestName,
      expectedRequest,
      responseName,
      {
        // There's no rule that says all the failed authentication responses HAVE to have the same oneof field name.
        // But in practice they do.
        failedAuthentication: {
          description: 'bad auth',
        },
      },
      sendRequest
    );
    await expect(responseFuture)
      .to.eventually.be.rejectedWith(LibSignalErrorBase)
      .and.deep.include({
        code: ErrorCode.RequestUnauthorized,
      });
  }

  const BACKUP_REQUEST_TEMPLATE: Record<string, unknown> = {
    signedPresentation: {
      presentation: toBase64(EXPECTED_PRESENTATION),
      presentationSignature: toBase64(EXPECTED_SIGNATURE),
    },
  };

  it('setPublicKey', async () => {
    await testSimpleGrpcRequest(
      'org.signal.chat.backup.SetPublicKeyRequest',
      { publicKey: toBase64(TEST_SIGNING_KEY_PUB), ...BACKUP_REQUEST_TEMPLATE },
      'org.signal.chat.backup.SetPublicKeyResponse',
      { success: {} },
      (chat) =>
        chat.setBackupPublicKey({
          auth: TEST_AUTH,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
    await testSimpleBackupRequestUnauthorized(
      'org.signal.chat.backup.SetPublicKeyRequest',
      { publicKey: toBase64(TEST_SIGNING_KEY_PUB), ...BACKUP_REQUEST_TEMPLATE },
      'org.signal.chat.backup.SetPublicKeyResponse',
      (chat) =>
        chat.setBackupPublicKey({
          auth: TEST_AUTH,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
  });

  it('getCdnCredentials', async () => {
    const credentials = await testSimpleGrpcRequest(
      'org.signal.chat.backup.GetCdnCredentialsRequest',
      { cdn: 40, ...BACKUP_REQUEST_TEMPLATE },
      'org.signal.chat.backup.GetCdnCredentialsResponse',
      {
        cdnCredentials: {
          headers: {
            b: 'bbb',
            a: 'aaa',
          },
        },
      },
      (chat) =>
        chat.getBackupCdnCredentials({
          auth: TEST_AUTH,
          cdn: 40,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
    expect(credentials).to.deep.equal({
      headers: new Map([
        ['a', 'aaa'],
        ['b', 'bbb'],
      ]),
    });

    await testSimpleBackupRequestUnauthorized(
      'org.signal.chat.backup.GetCdnCredentialsRequest',
      { cdn: 40, ...BACKUP_REQUEST_TEMPLATE },
      'org.signal.chat.backup.GetCdnCredentialsResponse',
      (chat) =>
        chat.getBackupCdnCredentials({
          auth: TEST_AUTH,
          cdn: 40,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
  });

  it('getSvrBCredentials', async () => {
    const credentials = await testSimpleGrpcRequest(
      'org.signal.chat.backup.GetSvrBCredentialsRequest',
      BACKUP_REQUEST_TEMPLATE,
      'org.signal.chat.backup.GetSvrBCredentialsResponse',
      {
        svrbCredentials: {
          username: 'user',
          password: 'pass',
        },
      },
      (chat) =>
        chat.getBackupSvrBCredentials({
          auth: TEST_AUTH,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
    expect(credentials).to.deep.equal({
      username: 'user',
      password: 'pass',
    });

    await testSimpleBackupRequestUnauthorized(
      'org.signal.chat.backup.GetSvrBCredentialsRequest',
      BACKUP_REQUEST_TEMPLATE,
      'org.signal.chat.backup.GetSvrBCredentialsResponse',
      (chat) =>
        chat.getBackupSvrBCredentials({
          auth: TEST_AUTH,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
  });

  it('refresh', async () => {
    await testSimpleGrpcRequest(
      'org.signal.chat.backup.RefreshRequest',
      BACKUP_REQUEST_TEMPLATE,
      'org.signal.chat.backup.RefreshResponse',
      {
        success: {},
      },
      (chat) =>
        chat.refreshBackup({
          auth: TEST_AUTH,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
    await testSimpleBackupRequestUnauthorized(
      'org.signal.chat.backup.RefreshRequest',
      BACKUP_REQUEST_TEMPLATE,
      'org.signal.chat.backup.RefreshResponse',
      (chat) =>
        chat.refreshBackup({
          auth: TEST_AUTH,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
  });

  it('deleteAll', async () => {
    await testSimpleGrpcRequest(
      'org.signal.chat.backup.DeleteAllRequest',
      BACKUP_REQUEST_TEMPLATE,
      'org.signal.chat.backup.DeleteAllResponse',
      {
        success: {},
      },
      (chat) =>
        chat.backupDeleteAll({
          auth: TEST_AUTH,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
    await testSimpleBackupRequestUnauthorized(
      'org.signal.chat.backup.DeleteAllRequest',
      BACKUP_REQUEST_TEMPLATE,
      'org.signal.chat.backup.DeleteAllResponse',
      (chat) =>
        chat.backupDeleteAll({
          auth: TEST_AUTH,
          rng: { __deterministicRngSeedForTesting: 0 },
        })
    );
  });
});

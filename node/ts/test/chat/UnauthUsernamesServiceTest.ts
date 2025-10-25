//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Buffer } from 'node:buffer';
import * as uuid from 'uuid';

import * as Native from '../../Native.js';
import * as util from '../util.js';
import { TokioAsyncContext, UnauthUsernamesService } from '../../net.js';
import { connectUnauth } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';
import { Aci } from '../../Address.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthUsernamesService', () => {
  describe('lookUpUsernameHash', () => {
    it('can look up hashes', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const hash = Uint8Array.of(1, 2, 3, 4);
      const responseFuture = chat.lookUpUsernameHash({ hash });

      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(
        `/v1/accounts/username_hash/${Buffer.from(hash).toString('base64url')}`
      );

      const aci = '4fcfe887-a600-40cd-9ab7-fd2a695e9981';

      fakeRemote.sendReplyTo(request, {
        status: 200,
        message: 'OK',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            uuid: aci,
          })
        ),
      });

      const responseFromServer = await responseFuture;
      assert(responseFromServer !== null);
      assert(Aci.fromUuid(aci).isEqual(responseFromServer));
    });

    it('can look up unknown hashes', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const hash = Uint8Array.of(1, 2, 3, 4);
      const responseFuture = chat.lookUpUsernameHash({ hash });

      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(
        `/v1/accounts/username_hash/${Buffer.from(hash).toString('base64url')}`
      );

      fakeRemote.sendReplyTo(request, {
        status: 404,
        message: 'Not Found',
      });

      const responseFromServer = await responseFuture;
      assert.isNull(responseFromServer);
    });

    it('can handle challenge errors', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const hash = Uint8Array.of(1, 2, 3, 4);
      const responseFuture = chat.lookUpUsernameHash({ hash });

      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(
        `/v1/accounts/username_hash/${Buffer.from(hash).toString('base64url')}`
      );

      fakeRemote.sendReplyTo(request, {
        status: 428,
        message: 'Precondition Required',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            token: 'not-legal-tender',
            options: ['pushChallenge'],
          })
        ),
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.RateLimitChallengeError,
          token: 'not-legal-tender',
          options: new Set(['pushChallenge']),
        });
    });

    it('can handle server errors', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const hash = Uint8Array.of(1, 2, 3, 4);
      const responseFuture = chat.lookUpUsernameHash({ hash });

      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(
        `/v1/accounts/username_hash/${Buffer.from(hash).toString('base64url')}`
      );

      fakeRemote.sendReplyTo(request, {
        status: 500,
        message: 'Internal Server Error',
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.IoError,
        });
    });
  });

  describe('lookUpUsernameLink', () => {
    const EXPECTED_USERNAME = 'moxie.01';
    const ENCRYPTED_USERNAME =
      'kj5ah-VbEgjpfJsNt-Wto2H626DRmJSVpYPy0yPOXA8kiSFkBCD8ysFlJ-Z3MhiAnt_R3Nm7ZY0W5fiRDLVbhaE2z-KO2xdf5NcVbkewCzhvveecS3hHskDp1aSfbvwTZNNGPmAuKWvJ1MPdHzsF0w';
    const ENCRYPTED_USERNAME_ENTROPY = Buffer.from(
      '4302c613c092a51c5394becffeb6f697300a605348e93f03c3db95e0b03d28f1',
      'hex'
    );

    it('can look up links', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const responseFuture = chat.lookUpUsernameLink({
        uuid: uuid.NIL,
        entropy: ENCRYPTED_USERNAME_ENTROPY,
      });

      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(
        '/v1/accounts/username_link/00000000-0000-0000-0000-000000000000'
      );

      fakeRemote.sendReplyTo(request, {
        status: 200,
        message: 'OK',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            usernameLinkEncryptedValue: ENCRYPTED_USERNAME,
          })
        ),
      });

      const responseFromServer = await responseFuture;
      assert.isNotNull(responseFromServer);
      assert.equal(responseFromServer.username, EXPECTED_USERNAME);
      assert.isNotEmpty(responseFromServer.hash);
    });

    it('can look up unknown links', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const responseFuture = chat.lookUpUsernameLink({
        uuid: uuid.NIL,
        entropy: ENCRYPTED_USERNAME_ENTROPY,
      });

      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(
        '/v1/accounts/username_link/00000000-0000-0000-0000-000000000000'
      );

      fakeRemote.sendReplyTo(request, {
        status: 404,
        message: 'Not Found',
      });

      const responseFromServer = await responseFuture;
      assert.isNull(responseFromServer);
    });

    it('can handle garbage ciphertexts', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const responseFuture = chat.lookUpUsernameLink({
        uuid: uuid.NIL,
        entropy: ENCRYPTED_USERNAME_ENTROPY,
      });

      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(
        '/v1/accounts/username_link/00000000-0000-0000-0000-000000000000'
      );

      fakeRemote.sendReplyTo(request, {
        status: 200,
        message: 'OK',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            usernameLinkEncryptedValue: `${ENCRYPTED_USERNAME}A`,
          })
        ),
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.InvalidUsernameLinkEncryptedData,
        });
    });

    it('can handle server errors', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const responseFuture = chat.lookUpUsernameLink({
        uuid: uuid.NIL,
        entropy: ENCRYPTED_USERNAME_ENTROPY,
      });

      const request = await fakeRemote.assertReceiveIncomingRequest();
      assert(request !== null);

      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq(
        '/v1/accounts/username_link/00000000-0000-0000-0000-000000000000'
      );

      fakeRemote.sendReplyTo(request, {
        status: 500,
        message: 'Internal Server Error',
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.IoError,
        });
    });

    it('can handle bad UUIDs', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, _fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const responseFuture = chat.lookUpUsernameLink({
        uuid: 'not',
        entropy: ENCRYPTED_USERNAME_ENTROPY,
      });

      await expect(responseFuture).to.eventually.be.rejectedWith(TypeError);
    });

    it('can handle bad entropy', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, _fakeRemote] = connectUnauth<UnauthUsernamesService>(tokio);

      const responseFuture = chat.lookUpUsernameLink({
        uuid: uuid.NIL,
        entropy: ENCRYPTED_USERNAME_ENTROPY.subarray(1),
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.InvalidEntropyDataLength,
        });
    });
  });
});

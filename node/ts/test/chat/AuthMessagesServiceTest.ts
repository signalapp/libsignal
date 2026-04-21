//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Buffer } from 'node:buffer';

import * as Native from '../../Native.js';
import * as util from '../util.js';
import { AuthMessagesService, TokioAsyncContext } from '../../net.js';
import { connectAuth } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';
import { FakeChatRemote, InternalRequest } from '../../net/FakeChat.js';
import { Aci } from '../../Address.js';
import { PlaintextContent } from '../../index.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthMessagesService', () => {
  describe('getUploadForm', () => {
    it('works correctly', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectAuth<AuthMessagesService>(tokio);
      const responseFuture = chat.getUploadForm({ uploadSize: 42n });
      const request = await fakeRemote.assertReceiveIncomingRequest();
      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq('/v4/attachments/form/upload?uploadLength=42');
      expect(request.headers.size).to.eq(0);
      expect(request.body.length).to.eq(0);
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
      const response = await responseFuture;
      expect(response).to.deep.eq({
        cdn: 123,
        key: 'abcde',
        headers: new Map([
          ['one', 'val1'],
          ['two', 'val2'],
        ]),
        signedUploadUrl: new URL('http://example.org/upload'),
      });
    });
    it('throws on upload too large', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectAuth<AuthMessagesService>(tokio);
      const responseFuture = chat.getUploadForm({ uploadSize: 42n });
      const request = await fakeRemote.assertReceiveIncomingRequest();
      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq('/v4/attachments/form/upload?uploadLength=42');
      expect(request.headers.size).to.eq(0);
      expect(request.body.length).to.eq(0);
      fakeRemote.sendReplyTo(request, {
        status: 413,
        message: 'Content Too Large',
      });
      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.UploadTooLarge,
        });
    });
  });

  describe('1:1 messages', () => {
    const recipientUuid = '4fcfe887-a600-40cd-9ab7-fd2a695e9981';

    async function sendTestMessage(
      chat: AuthMessagesService,
      syncMessage: boolean,
      fakeRemote: FakeChatRemote
    ): Promise<[Promise<void>, InternalRequest]> {
      const timestamp = 1700000000000;
      const contents = [
        {
          deviceId: 1,
          registrationId: 11,
          contents: PlaintextContent.deserialize(
            Uint8Array.of(0xc0, 1, 2, 3, 0x80)
          ).asCiphertextMessage(),
        },
        {
          deviceId: 2,
          registrationId: 22,
          contents: PlaintextContent.deserialize(
            Uint8Array.of(0xc0, 4, 5, 6, 0x80)
          ).asCiphertextMessage(),
        },
      ];
      const responseFuture = syncMessage
        ? chat.sendSyncMessage({ timestamp, contents, urgent: true })
        : chat.sendMessage({
            destination: Aci.fromUuid(recipientUuid),
            timestamp,
            contents,
            onlineOnly: false,
            urgent: true,
          });

      // Get the incoming request from the fake remote
      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('PUT');
      expect(request.path).to.eq(
        `/v1/messages/${
          syncMessage
            ? FakeChatRemote.FAKE_AUTH_CONNECT_SELF_UUID
            : recipientUuid
        }`
      );
      expect(request.headers).to.deep.eq(
        new Map([['content-type', 'application/json']])
      );
      expect(JSON.parse(new TextDecoder().decode(request.body))).to.deep.eq({
        messages: [
          {
            type: 8,
            destinationDeviceId: 1,
            destinationRegistrationId: 11,
            content: 'wAECA4A=',
          },
          {
            type: 8,
            destinationDeviceId: 2,
            destinationRegistrationId: 22,
            content: 'wAQFBoA=',
          },
        ],
        online: false,
        urgent: true,
        timestamp: 1700000000000,
      });

      return [responseFuture, request];
    }

    it('can send', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectAuth<AuthMessagesService>(tokio);

      for (const syncMessage of [false, true]) {
        const [responseFuture, request] = await sendTestMessage(
          chat,
          syncMessage,
          fakeRemote
        );

        fakeRemote.sendReplyTo(request, {
          status: 200,
          message: 'OK',
          headers: ['content-type: application/json'],
          body: Buffer.from('{}'),
        });

        await responseFuture;
      }
    });

    it('can handle NotFound', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectAuth<AuthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMessage(
        chat,
        false,
        fakeRemote
      );

      fakeRemote.sendReplyTo(request, {
        status: 404,
        message: 'Not Found',
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.ServiceIdNotFound,
        });
    });

    it('can handle a mismatched device error', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectAuth<AuthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMessage(
        chat,
        false,
        fakeRemote
      );

      fakeRemote.sendReplyTo(request, {
        status: 409,
        message: 'Conflict',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            missingDevices: [4, 5],
            extraDevices: [40, 50],
          })
        ),
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.MismatchedDevices,
          entries: [
            {
              account: Aci.fromUuid(recipientUuid),
              missingDevices: [4, 5],
              extraDevices: [40, 50],
              staleDevices: [],
            },
          ],
        });
    });

    it('can handle a stale device error', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectAuth<AuthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMessage(
        chat,
        false,
        fakeRemote
      );

      fakeRemote.sendReplyTo(request, {
        status: 410,
        message: 'Gone',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            staleDevices: [4, 5],
          })
        ),
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.MismatchedDevices,
          entries: [
            {
              account: Aci.fromUuid(recipientUuid),
              missingDevices: [],
              extraDevices: [],
              staleDevices: [4, 5],
            },
          ],
        });
    });

    it('can handle challenges', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectAuth<AuthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMessage(
        chat,
        false,
        fakeRemote
      );

      fakeRemote.sendReplyTo(request, {
        status: 428,
        message: 'Precondition Required',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            token: 'zzz',
            options: ['captcha'],
          })
        ),
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.RateLimitChallengeError,
          token: 'zzz',
          options: new Set(['captcha']),
        });
    });
  });
});

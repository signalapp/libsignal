//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Buffer } from 'node:buffer';

import * as Native from '../../Native.js';
import * as util from '../util.js';
import {
  MultiRecipientMessageResponse,
  TokioAsyncContext,
  UnauthMessagesService,
} from '../../net.js';
import { connectUnauth } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';
import { Aci } from '../../Address.js';
import { FakeChatRemote, InternalRequest } from '../../net/FakeChat.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthMessagesService', () => {
  describe('multi-recipient messages', () => {
    async function sendTestMultiRecipientMessage(
      chat: UnauthMessagesService,
      fakeRemote: FakeChatRemote
    ): Promise<[Promise<MultiRecipientMessageResponse>, InternalRequest]> {
      const payload = Uint8Array.of(1, 2, 3, 4);
      const timestamp = 1700000000000;
      const responseFuture = chat.sendMultiRecipientMessage({
        payload,
        timestamp,
        auth: 'story',
        onlineOnly: false,
        urgent: true,
      });

      // Get the incoming request from the fake remote
      const request = await fakeRemote.assertReceiveIncomingRequest();

      expect(request.verb).to.eq('PUT');
      expect(request.path).to.eq(
        '/v1/messages/multi_recipient?ts=1700000000000&online=false&urgent=true&story=true'
      );
      expect(request.headers).to.deep.eq(
        new Map([['content-type', 'application/vnd.signal-messenger.mrm']])
      );
      expect(request.body).to.deep.eq(payload);

      return [responseFuture, request];
    }

    it('can send', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMultiRecipientMessage(
        chat,
        fakeRemote
      );

      const uuid = '4fcfe887-a600-40cd-9ab7-fd2a695e9981';

      fakeRemote.sendReplyTo(request, {
        status: 200,
        message: 'OK',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify({
            uuids404: [uuid],
          })
        ),
      });

      const responseFromServer = await responseFuture;
      assert(responseFromServer !== null);
      expect(responseFromServer.unregisteredIds).to.deep.equal([
        Aci.fromUuid(uuid),
      ]);
    });

    it('can handle RequestUnauthorized', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMultiRecipientMessage(
        chat,
        fakeRemote
      );

      fakeRemote.sendReplyTo(request, {
        status: 401,
        message: 'Unauthorized',
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.RequestUnauthorized,
        });
    });

    it('can handle a mismatched device error', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMultiRecipientMessage(
        chat,
        fakeRemote
      );

      const uuid = '4fcfe887-a600-40cd-9ab7-fd2a695e9981';

      fakeRemote.sendReplyTo(request, {
        status: 409,
        message: 'Conflict',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify([
            {
              uuid,
              devices: {
                missingDevices: [4, 5],
                extraDevices: [40, 50],
              },
            },
          ])
        ),
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.MismatchedDevices,
          entries: [
            {
              account: Aci.fromUuid(uuid),
              missingDevices: [4, 5],
              extraDevices: [40, 50],
              staleDevices: [],
            },
          ],
        });
    });

    it('can handle a stale device error', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMultiRecipientMessage(
        chat,
        fakeRemote
      );

      const uuid = '4fcfe887-a600-40cd-9ab7-fd2a695e9981';

      fakeRemote.sendReplyTo(request, {
        status: 410,
        message: 'Gone',
        headers: ['content-type: application/json'],
        body: Buffer.from(
          JSON.stringify([
            {
              uuid,
              devices: {
                staleDevices: [4, 5],
              },
            },
          ])
        ),
      });

      await expect(responseFuture)
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.deep.include({
          code: ErrorCode.MismatchedDevices,
          entries: [
            {
              account: Aci.fromUuid(uuid),
              missingDevices: [],
              extraDevices: [],
              staleDevices: [4, 5],
            },
          ],
        });
    });

    it('can handle server-side errors', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthMessagesService>(tokio);

      const [responseFuture, request] = await sendTestMultiRecipientMessage(
        chat,
        fakeRemote
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
});

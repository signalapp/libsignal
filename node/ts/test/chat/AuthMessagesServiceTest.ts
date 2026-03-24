//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as Native from '../../Native.js';
import * as util from '../util.js';
import { TokioAsyncContext, AuthMessagesService } from '../../net.js';
import { connectAuth } from './ServiceTestUtils.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthMessagesService', () => {
  describe('getUploadForm', () => {
    it('works correctly', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectAuth<AuthMessagesService>(tokio);
      const responseFuture = chat.getUploadForm();
      const request = await fakeRemote.assertReceiveIncomingRequest();
      expect(request.verb).to.eq('GET');
      expect(request.path).to.eq('/v4/attachments/form/upload');
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
      expect(await responseFuture).to.deep.eq({
        cdn: 123,
        key: 'abcde',
        headers: new Map([
          ['one', 'val1'],
          ['two', 'val2'],
        ]),
        signedUploadUrl: new URL('http://example.org/upload'),
      });
    });
  });
});

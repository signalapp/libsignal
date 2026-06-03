//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as Native from '../../Native.js';
import * as util from '../util.js';
import { TokioAsyncContext, UnauthProfilesService } from '../../net.js';
import { connectUnauth } from './ServiceTestUtils.js';
import { Aci, Pni } from '../../Address.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthProfilesService', () => {
  describe('accountExists', () => {
    it('faithfully returns true or false', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthProfilesService>(tokio);

      const aci = Aci.fromUuid('9d0652a3-dcc3-4d11-975f-74d61598733f');
      const pni = Pni.fromUuid('796abedb-ca4e-4f18-8803-1fde5b921f9f');

      for (const testCase of [
        { serviceId: aci, found: true },
        { serviceId: pni, found: true },
        { serviceId: aci, found: false },
        { serviceId: pni, found: false },
      ]) {
        const responseFuture = chat.accountExists({
          account: testCase.serviceId,
        });
        const request = await fakeRemote.assertReceiveIncomingRequest();
        expect(request.verb).to.eq('HEAD');
        expect(request.path).to.eq(
          `/v1/accounts/account/${testCase.serviceId.getServiceIdString()}`
        );
        fakeRemote.sendReplyTo(request, {
          status: testCase.found ? 200 : 404,
          message: testCase.found ? 'OK' : 'Not Found',
        });
        expect(await responseFuture).to.eq(testCase.found);
      }
    });
  });
});

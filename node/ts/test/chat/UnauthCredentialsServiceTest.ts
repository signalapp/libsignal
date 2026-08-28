//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { UnauthCredentialsService } from '../../net.js';
import { connectUnauth, defineTestGrpcCases } from './ServiceTestUtils.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthCredentialsService', () => {
  describe('checkSvrCredentials', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_CheckSvrCredentialsTests(),
      connectUnauth<UnauthCredentialsService>,
      async (
        chat: UnauthCredentialsService,
        { number, passwords }: NativeNice.CheckSvrCredentialsArgs,
        resp: Array<[string, NativeNice.AuthCheckResult]>
      ) => {
        const out = await chat.checkSvrCredentials({
          number,
          credentials: passwords,
        });
        expect(out).to.deep.equal(new Map(resp));
      }
    );
  });
});

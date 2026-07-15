//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthAccountsService } from '../../net.js';
import { SvrKey } from '../../AccountKeys.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthAccountsService', () => {
  describe('setRegistrationLock', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_SetRegistrationLockTests(),
      connectAuth<AuthAccountsService>,
      async (
        chat: AuthAccountsService,
        svrKey: Uint8Array<ArrayBuffer>,
        _resp: void
      ) => {
        await chat.setRegistrationLock({ svrKey: new SvrKey(svrKey) });
      }
    );
  });
});

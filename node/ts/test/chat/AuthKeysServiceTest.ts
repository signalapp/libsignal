//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect } from 'chai';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthKeysService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';

util.initLogger();
config.truncateThreshold = 0;

describe('AuthKeysService', () => {
  describe('getPreKeyCount', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetPreKeyCountTests(),
      connectAuth<AuthKeysService>,
      async (
        chat: AuthKeysService,
        _args: void,
        resp: NativeNice.BridgePreKeyCounts
      ) => {
        const out = await chat.getPreKeyCount();
        expect(out).to.deep.equal(resp);
      }
    );
  });
});

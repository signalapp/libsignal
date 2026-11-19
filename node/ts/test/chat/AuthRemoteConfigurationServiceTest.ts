//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthRemoteConfigurationService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';
import type { TaggedBadges } from '../../NativeNice.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthRemoteConfigurationService', () => {
  describe('getBadges', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetBadgesTests(),
      connectAuth<AuthRemoteConfigurationService>,
      async (
        chat: AuthRemoteConfigurationService,
        etag: Uint8Array<ArrayBuffer> | null,
        resp: TaggedBadges | null
      ) => {
        const out = await chat.getBadges({ etag });
        expect(out).to.deep.equal(resp);
      }
    );
  });
});

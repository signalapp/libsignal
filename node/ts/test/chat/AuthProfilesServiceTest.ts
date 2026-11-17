//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthProfilesService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthProfilesService', () => {
  describe('getAvatarUploadFormLegacy', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetAvatarUploadFormLegacyTests(),
      connectAuth<AuthProfilesService>,
      async (
        chat: AuthProfilesService,
        { aci, profileKey }: NativeNice.GetAvatarUploadFormLegacyArgs,
        resp: NativeNice.S3UploadFormInternal
      ) => {
        const out = chat.getAvatarUploadFormLegacy({ aci, profileKey });
        expect(await out).to.deep.equal(resp);
      }
    );
  });
});

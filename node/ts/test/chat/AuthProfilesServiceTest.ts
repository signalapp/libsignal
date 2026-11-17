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
import type { AvatarUploadCredential } from '../../zkgroup/index.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';

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

  describe('getAvatarCredential', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetAvatarCredentialTests(),
      connectAuth<AuthProfilesService>,
      async (
        chat: AuthProfilesService,
        {
          aci,
          keyPair,
          rotationId,
          serverPublicParams,
          currentTimeSeconds,
        }: NativeNice.GetAvatarCredentialArgs,
        resp: AvatarUploadCredential | null
      ) => {
        const out = chat.getAvatarCredential({
          aci,
          keyPair,
          rotationId,
          serverPublicParams,
          currentTimeSeconds: Number(currentTimeSeconds),
          rng: { __deterministicRngSeedForTesting: 0 },
        });
        if (resp === null) {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.AccountMissingZkCredentialKey,
            });
        } else {
          expect(await out).to.deep.equal(resp);
        }
      }
    );
  });
});

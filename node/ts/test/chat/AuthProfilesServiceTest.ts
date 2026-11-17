//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as Native from '../../Native.js';
import * as util from '../util.js';
import {
  AuthProfilesService,
  AvatarCdnUrlValidationConfig,
  PROFILE_FIELD_MAX_LENGTHS,
  TokioAsyncContext,
} from '../../net.js';
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

  describe('setProfile', () => {
    async function check(
      chat: AuthProfilesService,
      {
        rngSeed,
        aci,
        profileKey,
        profile,
        expectedCurrentDataHash,
        expectedCurrentProfileKeyVersion,
        avatarCdnConfigValidUrls,
      }: NativeNice.SetProfileArgs,
      resp: NativeNice.SetProfileOut
    ): Promise<void> {
      const out = chat.setProfile({
        rng: { __deterministicRngSeedForTesting: Number(rngSeed) },
        aci,
        profileKey,
        profile,
        expectedCurrentDataHash,
        expectedCurrentProfileKeyVersion,
        avatarCdnUrlValidationConfig:
          AvatarCdnUrlValidationConfig.fromUrlPrefixes(
            avatarCdnConfigValidUrls
          ),
      });
      if ('success' in resp) {
        expect(await out).to.deep.equal(resp.success);
      } else if ('failure' in resp) {
        if (resp.failure === 'expectedDataWriteConflict') {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.SetProfileExpectedDataWriteConflict,
            });
        } else if (resp.failure === 'paymentsForbiddenInRegion') {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.SetProfilePaymentsForbiddenInRegion,
            });
        } else if (
          resp.failure ===
          'indeterminatePhoneNumberSharingDisallowedOnOutgoingProfiles'
        ) {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.IoError,
            });
        } else if ('invalidProfile' in resp.failure) {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.SetProfileInvalidProfile,
              profileValidationError: resp.failure.invalidProfile,
            });
        } else if ('expectedVersionWriteConflict' in resp.failure) {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.SetProfileExpectedVersionWriteConflict,
              currentProfileVersion: resp.failure.expectedVersionWriteConflict,
            });
        } else {
          resp.failure satisfies never;
          throw new Error('unreachable!');
        }
      } else {
        resp satisfies never;
        throw new Error('Unreachable!');
      }
    }
    describe('grpc tests', () => {
      defineTestGrpcCases(
        NativeNice.TESTING_SetProfileTests(),
        connectAuth<AuthProfilesService>,
        check
      );
    });
    describe('non-grpc tests', () => {
      for (const test of NativeNice.TESTING_SetProfileValidationTests()) {
        it(test.name, async () => {
          Native.TESTING_EnableDeterministicRngForTesting();
          const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
          const [chat, _fakeRemote] = connectAuth<AuthProfilesService>(tokio);
          await check(chat, test.request, test.response);
        });
      }
    });
    it('ProfileFieldWithMaxLength max lengths', () => {
      for (const [
        field,
        maxLength,
      ] of NativeNice.TESTING_ProfileFieldMaxLengths()) {
        expect(PROFILE_FIELD_MAX_LENGTHS[field]).equals(maxLength);
      }
    });
  });

  describe('getProfile', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetProfileTests(),
      connectAuth<AuthProfilesService>,
      async (
        chat: AuthProfilesService,
        {
          aci,
          profileKey,
          etag,
          avatarCdnConfigValidUrls,
        }: NativeNice.GetProfileArgs,
        resp: NativeNice.GetProfileOut
      ) => {
        const out = chat.getProfile({
          aci,
          profileKey,
          etag,
          avatarCdnUrlValidationConfig:
            AvatarCdnUrlValidationConfig.fromUrlPrefixes(
              avatarCdnConfigValidUrls
            ),
        });
        if ('success' in resp) {
          const profile = await out;
          expect(profile).to.deep.equal(resp.success);
          // chai will assume that all handles are equal, so we need to manually
          // compare the identity keys
          expect(profile?.identityKey?.serialize()).to.deep.equal(
            resp.success?.identityKey?.serialize()
          );
        } else if ('failure' in resp) {
          if (resp.failure === 'profileNotFound') {
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.ProfileNotFound,
              });
          } else if ('profileDecodeError' in resp.failure) {
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.ProfileCantBeDecoded,
              });
          } else {
            resp.failure satisfies never;
            throw new Error('Unreachable!');
          }
        } else {
          resp satisfies never;
          throw new Error('Unreachable!');
        }
      }
    );
  });
});

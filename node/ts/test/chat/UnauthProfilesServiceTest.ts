//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as Native from '../../Native.js';
import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { TokioAsyncContext, UnauthProfilesService } from '../../net.js';
import { connectUnauth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { Aci, Pni } from '../../Address.js';
import {
  AvatarUploadCredentialPresentation,
  ServerPublicParams,
} from '../../zkgroup/index.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthProfilesService', () => {
  describe('accountExists', () => {
    const grpcOverrides = ['AccountsAnonymousCheckAccountExistence'];

    it('faithfully returns true or false', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connectUnauth<UnauthProfilesService>(
        tokio,
        grpcOverrides
      );

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

  describe('getProfileKeyCredential', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetProfileKeyCredentialTests(),
      connectUnauth<UnauthProfilesService>,
      async (
        chat: UnauthProfilesService,
        {
          profileKeyRequestContext,
          serverParams,
        }: NativeNice.GetProfileKeyCredentialArgs,
        resp: NativeNice.GetProfileKeyCredentialOut
      ) => {
        const out = chat.getProfileKeyCredential({
          requestContext: profileKeyRequestContext,
          serverParams: new ServerPublicParams(serverParams.bytes),
        });
        if ('success' in resp) {
          expect(await out).to.deep.equal(resp.success);
        } else if ('unexpectedError' in resp) {
          await expect(out).to.eventually.be.rejectedWith(resp.unexpectedError);
        } else if ('explicitError' in resp) {
          let code: ErrorCode;
          switch (resp.explicitError) {
            case 'authFailed':
              code = ErrorCode.RequestUnauthorized;
              break;
            case 'profileNotFound':
              code = ErrorCode.ProfileNotFound;
              break;
            default:
              resp.explicitError satisfies never;
              throw new Error('Unreachable!');
          }
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({ code });
        } else {
          resp satisfies never;
          throw new Error('Unreachable!');
        }
      }
    );
  });

  describe('extendAvatarTtl', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_ExtendAvatarTtlTests(),
      connectUnauth<UnauthProfilesService>,
      async (
        chat: UnauthProfilesService,
        credential: AvatarUploadCredentialPresentation,
        resp: NativeNice.ExtendAvatarTtlOut
      ) => {
        const out = chat.extendAvatarTtl({ credential });
        if ('notFound' === resp) {
          expect(await out).to.eq(null);
        } else if ('invalidCredentials' === resp) {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.InvalidAvatarUploadCredentialPresentation,
            });
        } else if ('found' in resp) {
          expect(await out).to.deep.equal(resp.found);
        } else {
          resp satisfies never;
          throw new Error('Unreachable');
        }
      }
    );
  });

  describe('deleteAvatar', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_DeleteAvatarTests(),
      connectUnauth<UnauthProfilesService>,
      async (
        chat: UnauthProfilesService,
        credential: AvatarUploadCredentialPresentation,
        resp: boolean
      ) => {
        const out = chat.deleteAvatar({ credential });
        if (resp) {
          await out;
        } else {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.InvalidAvatarUploadCredentialPresentation,
            });
        }
      }
    );
  });

  describe('getAvatarUploadForm', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetAvatarUploadFormTests(),
      connectUnauth<UnauthProfilesService>,
      async (
        chat: UnauthProfilesService,
        { credential, uploadLength }: NativeNice.GetAvatarUploadFormArgs,
        resp: NativeNice.GetAvatarUploadFormOut
      ) => {
        const out = chat.getAvatarUploadForm({ credential, uploadLength });
        if (resp === 'invalidCredential') {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.InvalidAvatarUploadCredentialPresentation,
            });
        } else if ('success' in resp) {
          expect(await out).to.deep.equal(resp.success);
        } else {
          resp satisfies never;
          throw new Error('unreachable');
        }
      }
    );
  });

  describe('getProfile', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_UnauthGetProfileTests(),
      connectUnauth<UnauthProfilesService>,
      async (
        chat: UnauthProfilesService,
        {
          inner: { aci, profileKey, etag },
          auth,
        }: NativeNice.UnauthGetProfileArgs,
        resp: NativeNice.UnauthGetProfileOut
      ) => {
        const out = chat.getProfile({
          aci,
          profileKey,
          auth:
            'accessKey' in auth
              ? { accessKey: auth.accessKey }
              : auth.groupSend,
          etag,
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
          } else if (resp.failure === 'failedUnidentifiedAuthorization') {
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.RequestUnauthorized,
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

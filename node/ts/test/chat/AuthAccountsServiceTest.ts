//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as Native from '../../Native.js';
import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import {
  AuthAccountsService,
  MFA_KEY_NAME_MAX_LENGTH,
  TokioAsyncContext,
} from '../../net.js';
import { SvrKey } from '../../AccountKeys.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthAccountsService', () => {
  describe('deleteAccount', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_DeleteAccountTests(),
      connectAuth<AuthAccountsService>,
      async (chat: AuthAccountsService, _req: void, _resp: void) => {
        await chat.deleteAccount();
      }
    );
  });

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

  describe('clearRegistrationLock', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_ClearRegistrationLockTests(),
      connectAuth<AuthAccountsService>,
      async (chat: AuthAccountsService, _req: void, _resp: void) => {
        await chat.clearRegistrationLock();
      }
    );
  });

  describe('setRegistrationRecoveryPassword', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_SetRegistrationRecoveryPasswordTests(),
      connectAuth<AuthAccountsService>,
      async (
        chat: AuthAccountsService,
        svrKey: Uint8Array<ArrayBuffer>,
        _resp: void
      ) => {
        await chat.setRegistrationRecoveryPassword({
          svrKey: new SvrKey(svrKey),
        });
      }
    );
  });

  describe('setDiscoverableByPhoneNumber', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_SetDiscoverableByPhoneNumberTests(),
      connectAuth<AuthAccountsService>,
      async (chat: AuthAccountsService, discoverable: boolean, _resp: void) => {
        await chat.setDiscoverableByPhoneNumber({ discoverable });
      }
    );
  });

  describe('generateTotpKey', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GenerateTotpKeyTests(),
      connectAuth<AuthAccountsService>,
      async (
        chat: AuthAccountsService,
        _args: void,
        resp: NativeNice.GenerateTotpKeyOut
      ) => {
        const out = chat.generateTotpKey();
        switch (resp) {
          case 'tooManyTotpKeys':
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.TooManyTotpKeys,
              });
            break;
          case 'tooManyMfaKeys':
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.TooManyMfaKeys,
              });
            break;
          default:
            expect(await out).to.deep.equal(resp.success);
        }
      }
    );
  });

  describe('confirmTotpKey', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_ConfirmTotpKeyTests(),
      connectAuth<AuthAccountsService>,
      async (
        chat: AuthAccountsService,
        {
          oneTimePassword,
          name,
          createdAt,
          svrKey,
        }: NativeNice.ConfirmTotpKeyArgs,
        resp: NativeNice.ConfirmTotpKeyOut
      ) => {
        Native.TESTING_EnableDeterministicRngForTesting();
        const out = chat.confirmTotpKey({
          oneTimePassword,
          metadata: { name, createdAt },
          svrKey: new SvrKey(svrKey),
          rng: { __deterministicRngSeedForTesting: 0 },
        });
        switch (resp) {
          case 'oneTimePasswordNotVerified':
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.OneTimePasswordNotVerified,
              });
            break;
          case 'tooManyMfaKeys':
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.TooManyMfaKeys,
              });
            break;
          default:
            expect(await out).to.equal(resp.success);
        }
      }
    );
  });

  describe('listMfaKeys', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_ListMfaKeysTests(),
      connectAuth<AuthAccountsService>,
      async (
        chat: AuthAccountsService,
        { svrKey }: NativeNice.ListMfaKeysArgs,
        resp: NativeNice.ListMfaKeysOut
      ) => {
        const out = await chat.listMfaKeys({ svrKey: new SvrKey(svrKey) });
        expect(out).to.deep.equal(
          resp.success.map(({ id, metadata, kind }) => ({
            id,
            metadata: metadata === 'unreadable' ? null : metadata.metadata,
            kind,
          }))
        );
      }
    );
  });

  describe('setMfaKeyMetadata', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_SetMfaKeyMetadataTests(),
      connectAuth<AuthAccountsService>,
      async (
        chat: AuthAccountsService,
        { keyId, name, createdAt, svrKey }: NativeNice.SetMfaKeyMetadataArgs,
        resp: NativeNice.SetMfaKeyMetadataOut
      ) => {
        Native.TESTING_EnableDeterministicRngForTesting();
        const out = chat.setMfaKeyMetadata({
          keyId,
          metadata: { name, createdAt },
          svrKey: new SvrKey(svrKey),
          rng: { __deterministicRngSeedForTesting: 0 },
        });
        switch (resp) {
          case 'success':
            await out;
            break;
          case 'keyNotFound':
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.MfaKeyNotFound,
              });
            break;
          default:
            resp satisfies never;
        }
      }
    );
  });

  describe('argument validation', () => {
    const svrKey = new SvrKey(new Uint8Array(32));
    for (const [description, name] of [
      ['too-long', 'a'.repeat(MFA_KEY_NAME_MAX_LENGTH + 1)],
      ['NUL-containing', 'before\0after'],
    ] as const) {
      it(`rejects a ${description} name`, async () => {
        const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
        const [chat] = connectAuth<AuthAccountsService>(tokio);
        const metadata = { name, createdAt: 0 };
        await expect(
          chat.confirmTotpKey({
            oneTimePassword: 123456,
            metadata,
            svrKey,
          })
        )
          .to.eventually.be.rejectedWith(LibSignalErrorBase)
          .and.deep.include({ code: ErrorCode.Generic });
        await expect(chat.setMfaKeyMetadata({ keyId: 0, metadata, svrKey }))
          .to.eventually.be.rejectedWith(LibSignalErrorBase)
          .and.deep.include({ code: ErrorCode.Generic });
      });
    }

    for (const [description, createdAt] of [
      ['a negative', -1],
      ['a NaN', Number.NaN],
      ['an infinite', Number.POSITIVE_INFINITY],
      ['a fractional', 0.5],
      ['an unsafe', Number.MAX_SAFE_INTEGER + 1],
    ] as const) {
      it(`rejects ${description} creation timestamp from both metadata APIs`, async () => {
        const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
        const [chat] = connectAuth<AuthAccountsService>(tokio);
        const metadata = { name: 'Work laptop', createdAt };

        await expect(
          chat.confirmTotpKey({
            oneTimePassword: 123456,
            metadata,
            svrKey,
          })
        )
          .to.eventually.be.rejectedWith(LibSignalErrorBase)
          .and.deep.include({ code: ErrorCode.Generic });
        await expect(chat.setMfaKeyMetadata({ keyId: 0, metadata, svrKey }))
          .to.eventually.be.rejectedWith(LibSignalErrorBase)
          .and.deep.include({ code: ErrorCode.Generic });
      });
    }

    it('rejects an out-of-range key ID', async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat] = connectAuth<AuthAccountsService>(tokio);
      // -1 is below the range; 128 is the first ID past it.
      for (const keyId of [-1, 128]) {
        await expect(chat.removeMfaKey({ keyId }))
          .to.eventually.be.rejectedWith(LibSignalErrorBase)
          .and.deep.include({ code: ErrorCode.Generic });
      }
    });
  });

  describe('removeMfaKey', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_RemoveMfaKeyTests(),
      connectAuth<AuthAccountsService>,
      async (
        chat: AuthAccountsService,
        { keyId }: NativeNice.RemoveMfaKeyArgs,
        resp: NativeNice.RemoveMfaKeyOut
      ) => {
        const out = chat.removeMfaKey({ keyId });
        switch (resp) {
          case 'success':
            await out;
            break;
          default:
            resp satisfies never;
        }
      }
    );
  });
});

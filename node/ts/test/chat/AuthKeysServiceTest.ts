//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect } from 'chai';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthKeysService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { KEMPublicKey, PublicKey } from '../../index.js';

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

  describe('setOneTimeEcPreKeys', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_SetOneTimeEcPreKeysTests(),
      connectAuth<AuthKeysService>,
      async (
        chat: AuthKeysService,
        { identity, preKeys }: NativeNice.SetOneTimeEcPreKeysArgs,
        _resp: void
      ) => {
        await chat.setOneTimeEcPreKeys({
          identity,
          preKeys: preKeys.map(([keyId, publicKey]) => ({
            keyId: keyId,
            publicKey: PublicKey.deserialize(publicKey),
          })),
        });
      }
    );
  });

  describe('setOneTimeKemPreKeys', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_SetOneTimeKemPreKeysTests(),
      connectAuth<AuthKeysService>,
      async (
        chat: AuthKeysService,
        { identity, preKeys }: NativeNice.SetOneTimeKemPreKeysArgs,
        _resp: void
      ) => {
        await chat.setOneTimeKemPreKeys({
          identity,
          preKeys: preKeys.map((next) => ({
            keyId: next.id,
            publicKey: KEMPublicKey.deserialize(next.key),
            signature: next.sig,
          })),
        });
      }
    );
  });
});

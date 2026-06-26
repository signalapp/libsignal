//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthUsernamesService } from '../../net.js';
import { defineTestGrpcCasesAuth } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthUsernamesService', () => {
  describe('reserveUsernameHash', () => {
    defineTestGrpcCasesAuth(
      NativeNice.TESTING_ReserveUsernameHashTests(),
      async (
        chat: AuthUsernamesService,
        { usernames }: NativeNice.ReserveUsernameHashArgs,
        resp: NativeNice.ReserveUsernameHashOut
      ) => {
        const out = chat.reserveUsernameHash({
          usernameHashes: usernames,
        });
        if (resp === 'usernameNotAvailable') {
          expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.UsernameNotAvailable,
            });
        } else {
          expect(await out).to.deep.equal(resp.success);
        }
      }
    );
  });

  describe('setUsernameLink', () => {
    defineTestGrpcCasesAuth(
      NativeNice.TESTING_SetUsernameLinkTests(),
      async (
        chat: AuthUsernamesService,
        { usernameCiphertext, keepLinkHandle }: NativeNice.SetUsernameLinkArgs,
        resp: NativeNice.SetUsernameLinkOut
      ) => {
        const out = chat.setUsernameLink({
          usernameCiphertext,
          keepLinkHandle,
        });
        if (resp === 'usernameNotSet') {
          expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({
              code: ErrorCode.UsernameNotSet,
            });
        } else {
          expect(await out).to.deep.equal(resp.success);
        }
      }
    );
  });
});

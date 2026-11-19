//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { UnauthKeysService } from '../../net.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';
import { GroupSendFullToken } from '../../zkgroup/index.js';
import { connectUnauth, defineTestGrpcCases } from './ServiceTestUtils.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthKeysService', () => {
  describe('getPreKeys', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetPreKeysTests(),
      connectUnauth<UnauthKeysService>,
      async (chat, request, expected) => {
        const { target, deviceId } = request;
        const auth =
          typeof request.auth === 'object' && 'groupSendToken' in request.auth
            ? new GroupSendFullToken(request.auth.groupSendToken)
            : request.auth;

        const result = chat.getPreKeys({
          target,
          device: deviceId < 0 ? 'all' : { deviceId },
          auth,
        });

        if (typeof expected === 'object') {
          const { identityKey, preKeyBundles } = await result;
          expect(identityKey.serialize()).to.deep.equal(
            expected.success.identityKey
          );
          expect(preKeyBundles).to.have.length(expected.success.bundleCount);
          return;
        }

        if (expected === 'unexpected') {
          await expect(result).to.be.rejected;
          return;
        }

        await expect(result)
          .to.eventually.be.rejectedWith(LibSignalErrorBase)
          .and.deep.include({
            code:
              expected === 'notFound'
                ? ErrorCode.ServiceIdNotFound
                : ErrorCode.RequestUnauthorized,
          });
      }
    );
  });
});

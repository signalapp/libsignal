//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthStickersService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthStickersService', () => {
  describe('getStickerUploadForms', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetStickerUploadFormTests(),
      connectAuth<AuthStickersService>,
      async (
        chat: AuthStickersService,
        numberOfStickers: number,
        resp: NativeNice.GetStickerUploadFormsOut
      ) => {
        const out = chat.getStickerUploadForms({ numberOfStickers });
        if (typeof resp === 'object') {
          await expect(out).to.eventually.deep.equal(resp.success);
        } else {
          switch (resp) {
            case 'invalid':
              await expect(out)
                .to.eventually.be.rejectedWith(LibSignalErrorBase)
                .and.deep.include({
                  code: ErrorCode.IoError,
                });
              break;
            default:
              resp satisfies never;
          }
        }
      }
    );
  });
});

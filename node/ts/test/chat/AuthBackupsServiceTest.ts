//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthBackupsService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';
import { ReceiptCredentialPresentation } from '../../zkgroup/index.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthBackupsService', () => {
  describe('redeemBackupReceipt', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_RedeemBackupReceiptTests(),
      connectAuth<AuthBackupsService>,
      async (
        chat: AuthBackupsService,
        presentation: Uint8Array<ArrayBuffer>,
        resp: NativeNice.RedeemBackupReceiptOut
      ) => {
        const out = chat.redeemBackupReceipt({
          presentation: new ReceiptCredentialPresentation(presentation),
        });
        switch (resp) {
          case 'success':
            await out;
            break;
          case 'invalidReceipt':
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.InvalidReceipt,
              });
            break;
          case 'missingBackupId':
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.MissingBackupId,
              });
            break;
          case 'missingResponse':
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
    );
  });
});

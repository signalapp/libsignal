//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthDonationsService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { ServerPublicParams } from '../../zkgroup/index.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthDonationsService', () => {
  describe('redeemDonationReceipt', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_RedeemDonationReceiptTests(),
      connectAuth<AuthDonationsService>,
      async (
        chat: AuthDonationsService,
        { presentation, visibility }: NativeNice.RedeemDonationReceiptArgs,
        resp: NativeNice.RedeemDonationReceiptOut
      ) => {
        const out = chat.redeemDonationReceipt({
          presentation,
          badgeVisibility: visibility,
        });
        if (resp === 'success') {
          await out;
        } else if (resp === 'invalidReceipt') {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({ code: ErrorCode.InvalidReceipt });
        } else if (resp === 'alreadyRedeemed') {
          await expect(out)
            .to.eventually.be.rejectedWith(LibSignalErrorBase)
            .and.deep.include({ code: ErrorCode.ReceiptAlreadyRedeemed });
        } else if ('unexpectedError' in resp) {
          await expect(out).to.eventually.be.rejectedWith(resp.unexpectedError);
        } else {
          resp satisfies never;
          throw new Error('Unreachable!');
        }
      }
    );
  });

  describe('createDonationPermits', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_CreateDonationPermitsTests(),
      connectAuth<AuthDonationsService>,
      async (
        chat: AuthDonationsService,
        { requestContext, serverParams }: NativeNice.CreateDonationPermitsArgs,
        resp: NativeNice.CreateDonationPermitsOut
      ) => {
        const out = chat.createDonationPermits({
          requestContext,
          serverParams: new ServerPublicParams(serverParams.bytes),
        });
        if ('success' in resp) {
          expect(await out).to.deep.equal(resp.success);
        } else if ('unexpectedError' in resp) {
          await expect(out).to.eventually.be.rejectedWith(resp.unexpectedError);
        } else {
          resp satisfies never;
          throw new Error('Unreachable!');
        }
      }
    );
  });
});

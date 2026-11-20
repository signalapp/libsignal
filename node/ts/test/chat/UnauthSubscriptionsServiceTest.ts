//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { UnauthSubscriptionsService } from '../../net.js';
import { connectUnauth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';
import { ServerPublicParams } from '../../zkgroup/index.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthSubscriptionsService', () => {
  describe('getSubscriptionReceiptCredential', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetSubscriptionReceiptCredentialTests(),
      connectUnauth<UnauthSubscriptionsService>,
      async (
        chat: UnauthSubscriptionsService,
        {
          subscriberId,
          receiptCredentialRequestContext,
          serverParams,
        }: NativeNice.GetSubscriptionReceiptCredentialArgs,
        resp: NativeNice.GetSubscriptionReceiptCredentialOut
      ) => {
        const out = chat.getSubscriptionReceiptCredential({
          subscriberId,
          receiptCredentialRequestContext,
          serverParams: new ServerPublicParams(serverParams.bytes),
        });
        if ('success' in resp) {
          expect(await out).to.deep.equal(resp.success);
        } else if ('unexpectedError' in resp) {
          await expect(out).to.eventually.be.rejectedWith(resp.unexpectedError);
        } else if ('explicitError' in resp) {
          if (typeof resp.explicitError === 'string') {
            const codes: Record<
              | 'paymentNotFound'
              | 'paymentStillProcessing'
              | 'receiptAlreadyIssued',
              ErrorCode
            > = {
              paymentNotFound: ErrorCode.ReceiptCredentialErrorPaymentNotFound,
              paymentStillProcessing:
                ErrorCode.ReceiptCredentialErrorPaymentStillProcessing,
              receiptAlreadyIssued:
                ErrorCode.ReceiptCredentialErrorReceiptAlreadyIssued,
            };
            const code = codes[resp.explicitError];
            if (code === undefined) {
              throw new Error('Invalid code!');
            }
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({ code });
          } else {
            const chargeFailure =
              resp.explicitError.paymentRequired.length > 0
                ? resp.explicitError.paymentRequired[0]
                : null;
            await expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.ReceiptCredentialErrorPaymentRequired,
                chargeFailure,
              });
          }
        } else {
          resp satisfies never;
          throw new Error('Unreachable!');
        }
      }
    );
  });

  describe('getPurchaseProductConfiguration', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetProductConfigurationTests(),
      connectUnauth<UnauthSubscriptionsService>,
      async (
        chat: UnauthSubscriptionsService,
        _args: void,
        resp: NativeNice.PurchaseProductConfiguration
      ) => {
        const out = await chat.getPurchaseProductConfiguration({});
        // Adjust the expected value to u64 instead of i64.
        resp.login.level = BigInt.asUintN(64, resp.login.level);
        expect(out).to.deep.equal(resp);
        // Double-check signedness of bigints.
        expect(out.login.level).greaterThanOrEqual(0);
        void expect(out.backup.levels.keys().every((value) => value >= 0)).to.be
          .true;
      }
    );
  });
});

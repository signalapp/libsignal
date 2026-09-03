//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { UnauthLoginPurchaseService } from '../../net.js';
import { connectUnauth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';
import { ServerPublicParams } from '../../zkgroup/index.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthLoginPurchaseService', () => {
  describe('createLoginReceiptCredential', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_CreateLoginReceiptCredentialTests(),
      connectUnauth<UnauthLoginPurchaseService>,
      async (
        chat: UnauthLoginPurchaseService,
        {
          paymentProcessor,
          purchaseIdentifier,
          receiptCredentialRequestContext,
          serverParams,
          purchaseTime,
        }: NativeNice.CreateLoginReceiptCredentialArgs,
        resp: NativeNice.CreateLoginReceiptCredentialOut
      ) => {
        const out = chat.createLoginReceiptCredential({
          paymentProcessor,
          purchaseIdentifier,
          receiptCredentialRequestContext,
          serverParams: new ServerPublicParams(serverParams.bytes),
          purchaseTime,
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
});

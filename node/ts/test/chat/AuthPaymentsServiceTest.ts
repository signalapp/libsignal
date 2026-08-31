//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthPaymentsService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthPaymentsService', () => {
  describe('getCurrencyConversions', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetCurrencyConversionsTests(),
      connectAuth<AuthPaymentsService>,
      async (
        chat: AuthPaymentsService,
        _args: void,
        { timestampMs, currencies }: NativeNice.CurrencyConversionsInternal
      ) => {
        const out = await chat.getCurrencyConversions();
        expect({
          timestampMs,
          currencies: currencies.map(({ base, conversions }) => ({
            base,
            conversions: new Map(conversions),
          })),
        }).to.deep.equal(out);
      }
    );
  });
});

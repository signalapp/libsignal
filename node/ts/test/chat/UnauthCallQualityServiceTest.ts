//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { UnauthCallQualityService, CallQualitySurvey } from '../../net.js';
import { connectUnauth, defineTestGrpcCases } from './ServiceTestUtils.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('UnauthCallQualityService', () => {
  describe('submitCallQualitySurvey', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_SubmitCallQualitySurveyTests(),
      connectUnauth<UnauthCallQualityService>,
      async (
        chat: UnauthCallQualityService,
        survey: CallQualitySurvey,
        _resp: void
      ) => {
        await chat.submitCallQualitySurvey({ survey });
      }
    );
  });
});

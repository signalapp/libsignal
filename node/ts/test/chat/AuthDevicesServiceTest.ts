//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthDevicesService } from '../../net.js';
import { defineTestGrpcCasesAuth } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthDevicesService', () => {
  describe('setDeviceName', () => {
    defineTestGrpcCasesAuth(
      NativeNice.TESTING_SetDeviceNameTests(),
      async (
        chat: AuthDevicesService,
        { id, encryptedName }: NativeNice.SetDeviceNameArgs,
        resp: NativeNice.SetDeviceNameOut
      ) => {
        const out = chat.setDeviceName({
          deviceId: id,
          encryptedName,
        });
        switch (resp) {
          case 'success':
            await out;
            break;
          case 'deviceNotFound':
            expect(out)
              .to.eventually.be.rejectedWith(LibSignalErrorBase)
              .and.deep.include({
                code: ErrorCode.DeviceIdNotFound,
              });
            break;
          default:
            resp satisfies never;
        }
      }
    );
  });
});

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as NativeNice from '../../NativeNice.js';
import * as util from '../util.js';
import { AuthDevicesService } from '../../net.js';
import { connectAuth, defineTestGrpcCases } from './ServiceTestUtils.js';
import { ErrorCode, LibSignalErrorBase } from '../../Errors.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

describe('AuthDevicesService', () => {
  describe('setDeviceName', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_SetDeviceNameTests(),
      connectAuth<AuthDevicesService>,
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

  describe('removeDevice', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_RemoveDeviceTests(),
      connectAuth<AuthDevicesService>,
      async (
        chat: AuthDevicesService,
        { id }: NativeNice.RemoveDeviceArgs,
        resp: NativeNice.RemoveDeviceOut
      ) => {
        const out = chat.removeDevice({ deviceId: id });
        switch (resp) {
          case 'success':
            await out;
            break;
          default:
            resp satisfies never;
        }
      }
    );
  });

  describe('getDevices', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_GetDevicesTests(),
      connectAuth<AuthDevicesService>,
      async (
        chat: AuthDevicesService,
        _args: void,
        resp: NativeNice.GetDevicesOut
      ) => {
        const out = await chat.getDevices();
        expect(out).to.deep.equal(resp.devices);
      }
    );
  });

  describe('clearPushToken', () => {
    defineTestGrpcCases(
      NativeNice.TESTING_ClearPushTokenTests(),
      connectAuth<AuthDevicesService>,
      async (chat: AuthDevicesService, _args: void, _resp: void) => {
        await chat.clearPushToken();
      }
    );
  });
});

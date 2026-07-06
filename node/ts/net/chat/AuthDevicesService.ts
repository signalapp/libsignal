//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import { DeviceIdNotFound } from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthDevicesService {}
}

export interface AuthDevicesService {
  /**
   * Set the name of the given device ID to the provided encrypted name.
   *
   * @param encryptedName Must be between 1 and 225 bytes long
   *
   * @throws {DeviceIdNotFound} if the device id is invalid.
   */
  setDeviceName: (
    request: {
      deviceId: number;
      encryptedName: Uint8Array<ArrayBuffer>;
    },
    options?: RequestOptions
  ) => Promise<void>;
}

AuthenticatedChatConnection.prototype.setDeviceName = async function (
  {
    deviceId,
    encryptedName,
  }: {
    deviceId: number;
    encryptedName: Uint8Array<ArrayBuffer>;
  },
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_set_device_name({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    deviceId,
    encryptedName,
  });
};

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import { DeviceIdNotFound, type StandardNetworkError } from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthDevicesService {}
}

export type LinkedDevice = {
  /**
   * The account-local DeviceId for the device
   */
  id: number;
  /**
   * A sequence of bytes that encodes an encrypted human-readable name for
   * this device.
   */
  encryptedName: Uint8Array<ArrayBuffer>;
  /**
   * The approximate time, in milliseconds since the epoch, at which this
   * device last connected to the server.
   */
  lastSeen: number;
  /**
   * The registration ID of the given device.
   */
  registrationId: number;
  /**
   * A sequence of bytes that encodes the time, in milliseconds, since the epoch, at which this
   * device was attached to its parent account.
   */
  createdAtCiphertext: Uint8Array<ArrayBuffer>;
};

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
  /**
   * Remove a linked device from the current account.
   *
   * Linked devices may only remove themselves, and primary devices may remove
   * any device other than themselves; the server rejects anything else as a
   * programmer error.
   *
   * Removing a device ID that is not on the account also succeeds, so a caller
   * retrying a removal sees the same result as the original call. This is not
   * true idempotency, though: device IDs are small and get reused, so if a new
   * device is linked and assigned `deviceId` between two calls, the second call
   * removes that new device.
   *
   * @throws {StandardNetworkError}
   */
  removeDevice: (
    request: {
      deviceId: number;
    },
    options?: RequestOptions
  ) => Promise<void>;
  /**
   * List the devices associated with the current account.
   *
   * @throws {StandardNetworkError}
   */
  getDevices: (options?: RequestOptions) => Promise<Array<LinkedDevice>>;
  /**
   * Remove any push tokens associated with the current device.
   *
   * After this call, the server will assume the current device will
   * periodically poll for new messages.
   *
   * @throws {StandardNetworkError}
   */
  clearPushToken: (options?: RequestOptions) => Promise<void>;
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

AuthenticatedChatConnection.prototype.removeDevice = async function (
  {
    deviceId,
  }: {
    deviceId: number;
  },
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_remove_device({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    deviceId,
  });
};

AuthenticatedChatConnection.prototype.getDevices = async function (
  options?: RequestOptions
): Promise<Array<LinkedDevice>> {
  return await NativeNice.AuthenticatedChatConnection_get_devices({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

AuthenticatedChatConnection.prototype.clearPushToken = async function (
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_clear_push_token({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

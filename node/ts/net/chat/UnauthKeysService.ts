//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, UnauthenticatedChatConnection } from '../Chat.js';
import * as Native from '../../Native.js';
import { ServiceId } from '../../Address.js';
import { PublicKey } from '../../EcKeys.js';
import { PreKeyBundle } from '../../ProtocolTypes.js';
import GroupSendFullToken from '../../zkgroup/groupsend/GroupSendFullToken.js';
import type {
  RequestUnauthorizedError,
  ServiceIdNotFound,
} from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthKeysService {}
}

export interface UnauthKeysService {
  /**
   * Fetch the prekeys for a given target user
   *
   * @throws {RequestUnauthorizedError} if `auth` is not valid for the target
   * @throws {ServiceIdNotFound} if the requested identity or device does
   * not exist or device has no available prekeys.
   */
  getPreKeys: (
    request: {
      target: ServiceId;
      device: 'all' | { deviceId: number };
      auth:
        | { accessKey: Uint8Array<ArrayBuffer> }
        | GroupSendFullToken
        | 'unrestricted';
    },
    options?: RequestOptions
  ) => Promise<{
    identityKey: PublicKey;
    preKeyBundles: PreKeyBundle[];
  }>;
}

UnauthenticatedChatConnection.prototype.getPreKeys = async function (
  request: {
    auth:
      | { accessKey: Uint8Array<ArrayBuffer> }
      | GroupSendFullToken
      | 'unrestricted';
    target: ServiceId;
    device: 'all' | { deviceId: number };
  },
  options?: RequestOptions
): Promise<{
  identityKey: PublicKey;
  preKeyBundles: PreKeyBundle[];
}> {
  const device = request.device === 'all' ? -1 : request.device.deviceId;
  const { identityKey, preKeyBundles } =
    await this._asyncContext.makeCancellable(
      options?.abortSignal,
      request.auth === 'unrestricted'
        ? Native.UnauthenticatedChatConnection_get_pre_keys_unrestricted_auth(
            this._asyncContext,
            this._chatService,
            request.target.getServiceIdFixedWidthBinary(),
            device
          )
        : request.auth instanceof GroupSendFullToken
        ? Native.UnauthenticatedChatConnection_get_pre_keys_group_auth(
            this._asyncContext,
            this._chatService,
            request.auth.serialize(),
            request.target.getServiceIdFixedWidthBinary(),
            device
          )
        : Native.UnauthenticatedChatConnection_get_pre_keys_access_key_auth(
            this._asyncContext,
            this._chatService,
            request.auth.accessKey,
            request.target.getServiceIdFixedWidthBinary(),
            device
          )
    );
  return {
    identityKey: PublicKey._fromNativeHandle(identityKey),
    preKeyBundles: preKeyBundles.map((handle) =>
      PreKeyBundle._fromNativeHandle(handle)
    ),
  };
};

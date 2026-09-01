//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { StandardNetworkError } from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthKeysService {}
}

export type PreKeyCounts = {
  /**
   * The approximate number of one-time EC pre-keys stored for the
   * authenticated device and associated with the caller's ACI.
   */
  aciEcPreKeyCount: number;
  /**
   * The approximate number of one-time KEM pre-keys stored for the
   * authenticated device and associated with the caller's ACI.
   */
  aciKemPreKeyCount: number;
  /**
   * The approximate number of one-time EC pre-keys stored for the
   * authenticated device and associated with the caller's PNI.
   */
  pniEcPreKeyCount: number;
  /**
   * The approximate number of one-time KEM pre-keys stored for the
   * authenticated device and associated with the caller's PNI.
   */
  pniKemPreKeyCount: number;
};

export interface AuthKeysService {
  /**
   * Retrieves an approximate count of the number of the various kinds of
   * one-time pre-keys stored for the authenticated device.
   *
   * @throws {StandardNetworkError}
   */
  getPreKeyCount: (options?: RequestOptions) => Promise<PreKeyCounts>;
}

AuthenticatedChatConnection.prototype.getPreKeyCount = async function (
  options?: RequestOptions
): Promise<PreKeyCounts> {
  return await NativeNice.AuthenticatedChatConnection_get_pre_key_count({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

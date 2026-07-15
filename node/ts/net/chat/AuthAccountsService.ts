//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import { type StandardNetworkError } from '../../Errors.js';
import { SvrKey } from '../../AccountKeys.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthAccountsService {}
}

export interface AuthAccountsService {
  /**
   * Sets the registration lock for the authenticated account, given the account's SVR key (which
   * Signal clients historically call the "master key").
   *
   * libsignal derives the registration lock secret from the SVR key and sends only that secret;
   * the SVR key itself never leaves the device.
   *
   * While the registration lock is set, re-registering the account's phone number requires proving
   * knowledge of the secret.
   *
   * Only the account's primary device may set a registration lock.
   *
   * @param svrKey The account's SVR key, e.g. constructed from the bytes produced by
   * `AccountEntropyPool.deriveSvrKey`.
   *
   * @throws {StandardNetworkError}
   */
  setRegistrationLock: (
    request: {
      svrKey: SvrKey;
    },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Sets whether the authenticated account may be discovered by phone number via the Contact
   * Discovery Service (CDS).
   *
   * If `false`, other users must discover this account by other means (e.g. by username).
   *
   * @throws {StandardNetworkError}
   */
  setDiscoverableByPhoneNumber: (
    request: {
      discoverable: boolean;
    },
    options?: RequestOptions
  ) => Promise<void>;
}

AuthenticatedChatConnection.prototype.setRegistrationLock = async function (
  {
    svrKey,
  }: {
    svrKey: SvrKey;
  },
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_set_registration_lock({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    svrKey: svrKey.getContents(),
  });
};

AuthenticatedChatConnection.prototype.setDiscoverableByPhoneNumber =
  async function (
    {
      discoverable,
    }: {
      discoverable: boolean;
    },
    options?: RequestOptions
  ): Promise<void> {
    return await NativeNice.AuthenticatedChatConnection_set_discoverable_by_phone_number(
      {
        asyncContext: this.asyncContext,
        abortSignal: options?.abortSignal,
        chat: this.chatService,
        discoverable,
      }
    );
  };

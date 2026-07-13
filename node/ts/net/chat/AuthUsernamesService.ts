//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import {
  type UsernameNotAvailable,
  type UsernameNotSet,
  type StandardNetworkError,
} from '../../Errors.js';
import { type Uuid } from '../../uuid.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthUsernamesService {}
}

/**
 * A 32-byte username hash
 */
export type UsernameHash = Uint8Array<ArrayBuffer>;

export interface AuthUsernamesService {
  /**
   * Given a prioritized list of between 1 and 20 username hashes, try reserving them (in order)
   *
   * The first successfully reserved hash will be returned.
   * @param hashes Must contain between 1 and 20 usernames
   *
   * @throws {UsernameNotAvailable} if none of the usernames were avaialble
   */
  reserveUsernameHash: (
    request: {
      usernameHashes: UsernameHash[];
    },
    options?: RequestOptions
  ) => Promise<UsernameHash>;
  /**
   * For the given encrypted username, generate a username link handle. The username link handle
   * can be used to lookup the encrypted username.
   *
   * An account can only have one username link at a time; this endpoint overwrites the previous
   * encrypted username if there was one.
   *
   * @param usernameCiphertext must be between 1 and 128 bytes
   * @param keepLinkHandle If true and the account already had an encrypted username stored,
   * the existing link handle will be reused. Otherwise, a new link handle will be created.
   *
   * @throws {UsernameNotSet} if the account didn't have a username set
   * @throws {StandardNetworkError}
   */
  setUsernameLink: (
    request: {
      usernameCiphertext: Uint8Array<ArrayBuffer>;
      keepLinkHandle: boolean;
    },
    options?: RequestOptions
  ) => Promise<Uuid>;
  /**
   * Clears the current username hash, ciphertext, and link for the
   * authenticated account.
   *
   * This also succeeds if the account has no username set, so a caller
   * retrying a deletion sees the same result as the original call.
   *
   * @throws {StandardNetworkError}
   */
  deleteUsernameHash: (options?: RequestOptions) => Promise<void>;
  /**
   * Clears any username link associated with the authenticated account.
   *
   * The previously stored encrypted username is deleted and the link handle is
   * deactivated; the account's username hash (if any) is left in place. This
   * also succeeds if the account has no username link, so a caller retrying a
   * deletion sees the same result as the original call.
   *
   * @throws {StandardNetworkError}
   */
  deleteUsernameLink: (options?: RequestOptions) => Promise<void>;
}

AuthenticatedChatConnection.prototype.reserveUsernameHash = async function (
  {
    usernameHashes,
  }: {
    usernameHashes: UsernameHash[];
  },
  options?: RequestOptions
): Promise<UsernameHash> {
  return await NativeNice.AuthenticatedChatConnection_reserve_username_hash({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    usernameHashes,
  });
};

AuthenticatedChatConnection.prototype.setUsernameLink = async function (
  {
    usernameCiphertext,
    keepLinkHandle,
  }: {
    usernameCiphertext: Uint8Array<ArrayBuffer>;
    keepLinkHandle: boolean;
  },
  options?: RequestOptions
): Promise<Uuid> {
  return await NativeNice.AuthenticatedChatConnection_set_username_link({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    usernameCiphertext,
    keepLinkHandle,
  });
};

AuthenticatedChatConnection.prototype.deleteUsernameHash = async function (
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_delete_username_hash({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

AuthenticatedChatConnection.prototype.deleteUsernameLink = async function (
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_delete_username_link({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

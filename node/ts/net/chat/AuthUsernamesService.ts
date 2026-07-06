//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import { type UsernameNotAvailable } from '../../Errors.js';

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

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type {
  DonationPermit,
  DonationPermitRequestContext,
  ServerPublicParams,
} from '../../zkgroup/index.js';
import type { RateLimitedError, StandardNetworkError } from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthDonationsService {}
}

export interface AuthDonationsService {
  /**
   * Requests a batch of anonymous, single-use donation permits, one for each nonce in
   * `requestContext`.
   *
   * The server's response is verified against `serverParams` before the permits are returned,
   * in the same order as the nonces in `requestContext`.
   *
   * The server rate-limits each account by the number of permits requested, not the number of
   * requests. If the account doesn't have enough allowance left for the whole batch, nothing is
   * issued or used up and this fails with a {@link RateLimitedError}. The retry delay is how
   * long until the *full* batch would be allowed, so asking for fewer permits may succeed
   * sooner, even right away. A batch larger than the server's maximum allowance will never
   * succeed, no matter how long the caller waits.
   *
   * @throws {StandardNetworkError}
   */
  createDonationPermits: (
    request: {
      requestContext: DonationPermitRequestContext;
      serverParams: ServerPublicParams;
    },
    options?: RequestOptions
  ) => Promise<Array<DonationPermit>>;
}
AuthenticatedChatConnection.prototype.createDonationPermits = async function (
  { requestContext, serverParams },
  options?: RequestOptions
): Promise<Array<DonationPermit>> {
  return await NativeNice.AuthenticatedChatConnection_create_donation_permits({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    requestContext,
    serverParams,
  });
};

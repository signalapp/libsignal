//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { IsEqual } from 'type-fest';

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { AssertTrue } from '../../internal.js';
import type {
  DonationPermit,
  DonationPermitRequestContext,
  ReceiptCredentialPresentation,
  ServerPublicParams,
} from '../../zkgroup/index.js';
import type {
  InvalidReceiptError,
  RateLimitedError,
  ReceiptAlreadyRedeemed,
  StandardNetworkError,
} from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthDonationsService {}
}

/**
 * How a redeemed badge should appear on the account's profile.
 *
 * - `'doNotSet'`: Don't make the badge visible. A new badge starts out hidden, and a badge the
 *   account already shows stays visible.
 * - `'setVisible'`: Make the badge visible on the profile.
 * - `'setPrimary'`: Make the badge visible on the profile as the primary badge.
 */
export type BadgeVisibility = 'doNotSet' | 'setVisible' | 'setPrimary';

// Must be kept in sync with BadgeVisibility in rust/bridge/shared/types/src/net/chat.rs. This fails
// to compile if the generated NativeNice.BadgeVisibility has different cases.
type _BadgeVisibilityMatchesBridge = AssertTrue<
  IsEqual<BadgeVisibility, NativeNice.BadgeVisibility>
>;

export interface AuthDonationsService {
  /**
   * Redeems a donation receipt to add the corresponding badge to the account.
   *
   * After this succeeds, the account has the badge until the receipt's expiration time.
   * `badgeVisibility` controls whether it shows on the profile; see {@link BadgeVisibility}.
   *
   * Redeeming the same receipt again for the same account succeeds. A receipt that was already
   * redeemed by a different account fails with {@link ReceiptAlreadyRedeemed}.
   *
   * @throws {InvalidReceiptError} if the receipt credential presentation is invalid.
   * @throws {ReceiptAlreadyRedeemed} if the receipt was already redeemed.
   * @throws {StandardNetworkError}
   */
  redeemDonationReceipt: (
    request: {
      presentation: ReceiptCredentialPresentation;
      badgeVisibility: BadgeVisibility;
    },
    options?: RequestOptions
  ) => Promise<void>;

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

AuthenticatedChatConnection.prototype.redeemDonationReceipt = async function (
  { presentation, badgeVisibility },
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_redeem_donation_receipt({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    presentation,
    visibility: badgeVisibility,
  });
};

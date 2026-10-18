//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { Bytes } from '@signalapp/types';

import { RequestOptions, UnauthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import * as zkgroup from '../../zkgroup/index.js';
import type {
  ReceiptCredentialErrorPaymentNotFound,
  ReceiptCredentialErrorPaymentRequired,
  ReceiptCredentialErrorPaymentStillProcessing,
  ReceiptCredentialErrorReceiptAlreadyIssued,
  StandardNetworkError,
} from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthSubscriptionsService {}
}

export interface UnauthSubscriptionsService {
  /**
   * Obtain a ZK receipt credential for an active subscription.
   * The receipt credential can then be used to obtain an entitlement (e.g. a badge or backup tier).
   *
   * Retries must use an identical `receiptCredentialRequestContext`. After successfully receiving
   * the credential, the request context **must not** be reused again, or you may not be able to
   * redeem a valid payment invoice.
   *
   * Note that you may in fact redeem *multiple* invoices for the same request context while
   * retrying this operation if a later invoice gets paid while you are retrying. However, the
   * returned receipt is always for the latest invoice, so it will have the latest expiration
   * possible and no entitlement time will be lost.
   *
   * Clients **must** validate that the generated receipt credential's level matches their
   * expectations. In particular, if you are currently at subscription level 100, and send a
   * request to change to level 200, you may get a receipt for level 100 or level 200 until you
   * get a successful response for the level change request. (Consider a successful level change
   * request where the connection drops before the response makes it back to the client.)
   *
   * @throws {StandardNetworkError}
   * @throws {ReceiptCredentialErrorPaymentRequired} if the purchase did not complete successfully.
   * @throws {ReceiptCredentialErrorPaymentStillProcessing} if the most recent subscription renewal
   * has not happened yet. Retrying immediately is unlikely to help, but retrying later may succeed.
   * @throws {ReceiptCredentialErrorPaymentNotFound} indicates either that the `subscriberId` is not
   * associated with an active subscription, or that the server has no record of `subscriberId` at
   * all.
   * @throws {ReceiptCredentialErrorReceiptAlreadyIssued} if the purchase was already redeemed for a
   * receipt credential, but with a different receipt credential request.
   */
  getSubscriptionReceiptCredential: (
    request: {
      subscriberId: Bytes;
      receiptCredentialRequestContext: zkgroup.ReceiptCredentialRequestContext;
      serverParams: zkgroup.ServerPublicParams;
    },
    options?: RequestOptions
  ) => Promise<zkgroup.ReceiptCredential>;
}

UnauthenticatedChatConnection.prototype.getSubscriptionReceiptCredential =
  async function (
    { subscriberId, receiptCredentialRequestContext, serverParams },
    options?: RequestOptions
  ): Promise<zkgroup.ReceiptCredential> {
    return await NativeNice.UnauthenticatedChatConnection_get_subscription_receipt_credential(
      {
        asyncContext: this._asyncContext,
        abortSignal: options?.abortSignal,
        chat: this._chatService,
        subscriberId,
        receiptCredentialRequestContext,
        serverParams,
      }
    );
  };

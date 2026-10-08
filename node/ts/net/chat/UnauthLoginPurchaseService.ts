//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { IsEqual } from 'type-fest';

import { RequestOptions, UnauthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { AssertTrue } from '../../internal.js';
import * as zkgroup from '../../zkgroup/index.js';
import type {
  ReceiptCredentialErrorPaymentNotFound,
  ReceiptCredentialErrorPaymentRequired,
  ReceiptCredentialErrorPaymentStillProcessing,
  ReceiptCredentialErrorReceiptAlreadyIssued,
  StandardNetworkError,
} from '../../Errors.js';
import type { Timestamp } from '../../NiceConverters.js';
import type { PaymentProvider } from './PurchaseTypes.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthLoginPurchaseService {}
}

export type LoginReceiptLevel = 'normal' | 'sandbox';

// Must be kept in sync with LoginReceiptLevel in rust/bridge/shared/types/src/net/chat.rs. This
// fails to compile if the generated NativeNice.LoginReceiptLevel has different cases.
type _LoginReceiptLevelMatchesBridge = AssertTrue<
  IsEqual<LoginReceiptLevel, NativeNice.LoginReceiptLevel>
>;

export interface UnauthLoginPurchaseService {
  /**
   * Obtain a ZK receipt credential for a completed one-time login payment.
   * The receipt credential can then be presented at registration.
   *
   * Subsequent retries to create a login credential for the same `purchaseIdentifier` must use
   * an identical `receiptCredentialRequestContext`.
   *
   * @throws {StandardNetworkError}
   * @throws {ReceiptCredentialErrorPaymentRequired} if the purchase did not complete successfully.
   * @throws {ReceiptCredentialErrorPaymentStillProcessing} Should be rare if payment has already
   * been confirmed locally, but the client may retry the request.
   * @throws {ReceiptCredentialErrorPaymentNotFound} indicates that the server has no record of
   * `purchaseIdentifier`, which may be a client issue, a server issue, or a problem with the
   * payment processor; it is not worth retrying.
   * @throws {ReceiptCredentialErrorReceiptAlreadyIssued} if the purchase was already redeemed for a
   * receipt credential, but with a different receipt credential request.
   */
  createLoginReceiptCredential: (
    request: {
      paymentProcessor: PaymentProvider;
      purchaseIdentifier: string;
      receiptCredentialRequestContext: zkgroup.ReceiptCredentialRequestContext;
      serverParams: zkgroup.ServerPublicParams;
      purchaseTime: Timestamp;
      expectedLevel: LoginReceiptLevel;
    },
    options?: RequestOptions
  ) => Promise<zkgroup.ReceiptCredential>;
}
UnauthenticatedChatConnection.prototype.createLoginReceiptCredential =
  async function (
    {
      paymentProcessor,
      purchaseIdentifier,
      receiptCredentialRequestContext,
      serverParams,
      purchaseTime,
      expectedLevel,
    },
    options?: RequestOptions
  ): Promise<zkgroup.ReceiptCredential> {
    return await NativeNice.UnauthenticatedChatConnection_create_login_receipt_credential(
      {
        asyncContext: this._asyncContext,
        abortSignal: options?.abortSignal,
        chat: this._chatService,
        paymentProcessor,
        purchaseIdentifier,
        receiptCredentialRequestContext,
        serverParams,
        purchaseTime,
        expectedLevel,
      }
    );
  };

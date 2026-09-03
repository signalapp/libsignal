//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

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
import type { Timestamp } from '../../NiceConverters.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthLoginPurchaseService {}
}

export type PaymentProvider =
  | 'googlePlayBilling'
  | 'appleAppStore'
  | 'stripe'
  | 'braintree';

export type ReceiptCredentialError =
  | ReceiptCredentialErrorPaymentNotFound
  | ReceiptCredentialErrorPaymentRequired
  | ReceiptCredentialErrorPaymentStillProcessing
  | ReceiptCredentialErrorReceiptAlreadyIssued;

export interface UnauthLoginPurchaseService {
  /**
   * Obtain a ZK receipt credential for a completed one-time login payment.
   * The receipt credential can then be presented at registration.
   *
   * Subsequent retries to create a login credential for the same purchaseIdentifier must use
   * an identical receiptCredentialRequestContext.
   *
   * @throws {StandardNetworkError}
   * @throws {ReceiptCredentialError}
   */
  createLoginReceiptCredential: (
    request: {
      paymentProcessor: PaymentProvider;
      purchaseIdentifier: string;
      receiptCredentialRequestContext: zkgroup.ReceiptCredentialRequestContext;
      serverParams: zkgroup.ServerPublicParams;
      purchaseTime: Timestamp;
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
      }
    );
  };

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { IsEqual } from 'type-fest';

import type * as NativeNice from '../../NativeNice.js';
import type { AssertTrue } from '../../internal.js';
import type {
  ReceiptCredentialErrorPaymentNotFound,
  ReceiptCredentialErrorPaymentRequired,
  ReceiptCredentialErrorPaymentStillProcessing,
  ReceiptCredentialErrorReceiptAlreadyIssued,
} from '../../Errors.js';

export type PaymentProvider =
  | 'googlePlayBilling'
  | 'appleAppStore'
  | 'stripe'
  | 'braintree';

// Must be kept in sync with PaymentProvider in rust/bridge/shared/types/src/net/chat.rs. This fails
// to compile if the generated NativeNice.PaymentProvider has different cases.
type _PaymentProviderMatchesBridge = AssertTrue<
  IsEqual<PaymentProvider, NativeNice.PaymentProvider>
>;

export type ReceiptCredentialError =
  | ReceiptCredentialErrorPaymentNotFound
  | ReceiptCredentialErrorPaymentRequired
  | ReceiptCredentialErrorPaymentStillProcessing
  | ReceiptCredentialErrorReceiptAlreadyIssued;

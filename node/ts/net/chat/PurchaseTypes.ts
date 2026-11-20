//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { IsEqual } from 'type-fest';
import type {
  BigUint64,
  DurationDays,
  DurationSecs,
  UnitBytes,
} from '@signalapp/types';

import type * as NativeNice from '../../NativeNice.js';
import type { AssertTrue } from '../../internal.js';
import type {
  ReceiptCredentialErrorPaymentNotFound,
  ReceiptCredentialErrorPaymentRequired,
  ReceiptCredentialErrorPaymentStillProcessing,
  ReceiptCredentialErrorReceiptAlreadyIssued,
} from '../../Errors.js';
// eslint-disable-next-line @typescript-eslint/no-unused-vars -- doesn't understand JSDoc namepaths.
import type { AuthRemoteConfigurationService } from './AuthRemoteConfigurationService.js';

export type PaymentProvider =
  | 'googlePlayBilling'
  | 'appleAppStore'
  | 'stripe'
  | 'braintree';

// Must be kept in sync with PaymentProviderInternal in rust/bridge/shared/types/src/net/chat.rs.
// This fails to compile if the generated NativeNice.PaymentProviderInternal has different cases.
type _PaymentProviderMatchesBridge = AssertTrue<
  IsEqual<PaymentProvider, NativeNice.PaymentProviderInternal>
>;

export type PaymentMethod =
  | 'card'
  | 'sepaDebit'
  | 'ideal'
  | 'payPal'
  | 'googlePlayBilling'
  | 'appleAppStore';

// Must be kept in sync with PaymentMethodInternal in rust/bridge/shared/types/src/net/chat.rs.
// This fails to compile if the generated NativeNice.PaymentMethodInternal has different cases.
type _PaymentMethodMatchesBridge = AssertTrue<
  IsEqual<PaymentMethod, NativeNice.PaymentMethodInternal>
>;

export type PurchaseProductConfiguration = {
  /** A map of lower-cased ISO 3 currency codes to currency-specific configuration */
  currencies: Map<string, PurchaseProductConfiguration.CurrencyConfiguration>;
  /** A map of numeric donation level IDs to level-specific badge configuration */
  badgeLevels: Map<
    BigUint64,
    PurchaseProductConfiguration.BadgeLevelConfiguration
  >;
  /** Configuration for backup subscription options */
  backup: PurchaseProductConfiguration.BackupConfiguration;
  /** Maximum value of a one-time SEPA donation, in EUR [minor units](https://docs.stripe.com/currencies#minor-units) */
  sepaMaximumEuros: number;
  /** Configuration for one-time Signal Login purchases */
  login: PurchaseProductConfiguration.LoginConfiguration;
};
export namespace PurchaseProductConfiguration {
  export type CurrencyConfiguration = {
    /** Minimum one-time donation in the currency's [minor unit](https://docs.stripe.com/currencies#minor-units) */
    minimum: number;
    /** Map of one-time donation level IDs to suggested amounts in the currency's minor unit */
    oneTimeDonationAmounts: Map<BigUint64, Array<number>>;
    /** Map of subscription level IDs to the amount charged in the currency's minor unit */
    subscriptionAmounts: Map<BigUint64, number>;
    /** Map of backup subscription level IDs to the amount charged in the currency's minor unit */
    backupSubscriptionAmounts: Map<BigUint64, number>;
    /**
     * List of payment methods that support this currency.
     *
     * Note that this list may be empty if the only supported payment methods are newer than what
     * this version of libsignal understands.
     */
    supportedPaymentMethods: Array<PaymentMethod>;
  };
  export type BadgeLevelConfiguration = {
    /**
     * The ID of the badge awarded at this level.
     *
     * Can be resolved to full badge details via {@link AuthRemoteConfigurationService#getBadges}.
     */
    badgeId: string;
    /**
     * The duration for which a badge is valid.
     *
     * Present only for one-time badges (boosts and gifts).
     */
    badgeDurationSeconds: DurationSecs | null;
  };
  export type BackupConfiguration = {
    /** A map of numeric backup level IDs to level-specific backup configuration */
    levels: Map<BigUint64, BackupLevelConfiguration>;
    /** The number of days of media a free tier backup user gets */
    freeTierMediaDays: DurationDays;
  };
  export type BackupLevelConfiguration = {
    /** The amount of media storage in bytes that a paying subscriber may store */
    storageAllowanceBytes: UnitBytes;
    /** The Play Store billing productID associated with this backup level */
    playProductId: string;
    /** The duration, in days, for which your backed up media is retained on the server after you stop refreshing with a paid credential */
    mediaTtlDays: DurationDays;
  };
  export type LoginConfiguration = {
    /**
     * The receipt level associated with a Signal Login purchase.
     *
     * Should match your locally-expected level.
     */
    level: BigUint64;
    /** The Play Store billing productID associated with a Signal Login purchase */
    playProductId: string;
    /** The Play Store billing optionID to use to purchase a Signal Login */
    playOptionId: string;
    /** The Apple App Store productID associated with a Signal Login purchase */
    appStoreProductId: string;
  };
}

export type ReceiptCredentialError =
  | ReceiptCredentialErrorPaymentNotFound
  | ReceiptCredentialErrorPaymentRequired
  | ReceiptCredentialErrorPaymentStillProcessing
  | ReceiptCredentialErrorReceiptAlreadyIssued;

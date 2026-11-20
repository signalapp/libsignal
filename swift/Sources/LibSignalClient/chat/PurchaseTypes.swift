//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public enum PaymentProvider: Sendable, Equatable {
    case googlePlayBilling
    case appleAppStore
    case stripe
    case braintree
}

public enum PaymentMethod: Sendable, Equatable {
    case card
    case sepaDebit
    case ideal
    case payPal
    case googlePlayBilling
    case appleAppStore
}

public struct PurchaseProductConfiguration: Sendable, Equatable {
    /// A map of lower-cased ISO 3 currency codes to currency-specific configuration
    public var currencies: [String: CurrencyConfiguration]
    /// A map of numeric donation level IDs to level-specific badge configuration
    public var badgeLevels: [UInt64: BadgeLevelConfiguration]
    /// Configuration for backup subscription options
    public var backup: BackupConfiguration
    /// Maximum value of a one-time SEPA donation, in EUR [minor units](https://docs.stripe.com/currencies#minor-units)
    public var sepaMaximumEuros: UInt64
    /// Configuration for one-time Signal Login purchases
    public var login: LoginConfiguration

    public init(
        currencies: [String: CurrencyConfiguration],
        badgeLevels: [UInt64: BadgeLevelConfiguration],
        backup: BackupConfiguration,
        sepaMaximumEuros: UInt64,
        login: LoginConfiguration
    ) {
        self.currencies = currencies
        self.badgeLevels = badgeLevels
        self.backup = backup
        self.sepaMaximumEuros = sepaMaximumEuros
        self.login = login
    }

    public struct CurrencyConfiguration: Sendable, Equatable {
        /// Minimum one-time donation in the currency's [minor unit](https://docs.stripe.com/currencies#minor-units)
        public var minimum: UInt64
        /// Map of one-time donation level IDs to suggested amounts in the currency's minor unit
        public var oneTimeDonationAmounts: [UInt64: [UInt64]]
        /// Map of subscription level IDs to the amount charged in the currency's minor unit
        public var subscriptionAmounts: [UInt64: UInt64]
        /// Map of backup subscription level IDs to the amount charged in the currency's minor unit
        public var backupSubscriptionAmounts: [UInt64: UInt64]
        /// List of payment methods that support this currency.
        ///
        /// Note that this list may be empty if the only supported payment methods are newer than what
        /// this version of libsignal understands.
        public var supportedPaymentMethods: [PaymentMethod]

        public init(
            minimum: UInt64,
            oneTimeDonationAmounts: [UInt64: [UInt64]],
            subscriptionAmounts: [UInt64: UInt64],
            backupSubscriptionAmounts: [UInt64: UInt64],
            supportedPaymentMethods: [PaymentMethod]
        ) {
            self.minimum = minimum
            self.oneTimeDonationAmounts = oneTimeDonationAmounts
            self.subscriptionAmounts = subscriptionAmounts
            self.backupSubscriptionAmounts = backupSubscriptionAmounts
            self.supportedPaymentMethods = supportedPaymentMethods
        }
    }

    public struct BadgeLevelConfiguration: Sendable, Equatable {
        /// The ID of the badge awarded at this level.
        ///
        /// Can be resolved to full badge details via ``AuthRemoteConfigurationService/getBadges(etag:)``.
        public var badgeId: String
        /// The duration for which a badge is valid.
        ///
        /// Present only for one-time badges (boosts and gifts).
        public var badgeDuration: TimeInterval?

        public init(badgeId: String, badgeDuration: TimeInterval? = nil) {
            self.badgeId = badgeId
            self.badgeDuration = badgeDuration
        }

        internal init(badgeId: String, badgeDurationSeconds: UInt32?) {
            self.init(badgeId: badgeId, badgeDuration: badgeDurationSeconds.map { TimeInterval($0) })
        }
    }

    public struct BackupConfiguration: Sendable, Equatable {
        /// A map of numeric backup level IDs to level-specific backup configuration
        public var levels: [UInt64: BackupLevelConfiguration]
        /// The number of days of media a free tier backup user gets
        public var freeTierMediaDays: UInt32

        public init(levels: [UInt64: BackupLevelConfiguration], freeTierMediaDays: UInt32) {
            self.levels = levels
            self.freeTierMediaDays = freeTierMediaDays
        }
    }

    public struct BackupLevelConfiguration: Sendable, Equatable {
        /// The amount of media storage in bytes that a paying subscriber may store
        public var storageAllowanceBytes: UInt64
        /// The Play Store billing productID associated with this backup level
        public var playProductId: String
        /// The duration, in days, for which your backed up media is retained on the server after you stop refreshing with a paid credential
        public var mediaTtlDays: UInt32

        public init(storageAllowanceBytes: UInt64, playProductId: String, mediaTtlDays: UInt32) {
            self.storageAllowanceBytes = storageAllowanceBytes
            self.playProductId = playProductId
            self.mediaTtlDays = mediaTtlDays
        }
    }

    public struct LoginConfiguration: Sendable, Equatable {
        /// The receipt level associated with a Signal Login purchase.
        ///
        /// Should match your locally-expected level.
        public var level: UInt64
        /// The Play Store billing productID associated with a Signal Login purchase
        public var playProductId: String
        /// The Play Store billing optionID to use to purchase a Signal Login
        public var playOptionId: String
        /// The Apple App Store productID associated with a Signal Login purchase
        public var appStoreProductId: String

        public init(level: UInt64, playProductId: String, playOptionId: String, appStoreProductId: String) {
            self.level = level
            self.playProductId = playProductId
            self.playOptionId = playOptionId
            self.appStoreProductId = appStoreProductId
        }

        internal init(level: Int64, playProductId: String, playOptionId: String, appStoreProductId: String) {
            self.init(
                level: UInt64(bitPattern: level),
                playProductId: playProductId,
                playOptionId: playOptionId,
                appStoreProductId: appStoreProductId
            )
        }
    }
}

/// Information about a charge failure.
///
/// Meaningfully interpreting chargeFailure response fields requires inspecting the processor field
/// first.
///
/// For Stripe, code will be one of the [codes defined here](https://stripe.com/docs/api/charges/object#charge_object-failure_code),
/// while message [may contain a further textual description](https://stripe.com/docs/api/charges/object#charge_object-failure_message).
/// The outcome fields are optional, but present values will directly map to Stripe
/// [response properties](https://stripe.com/docs/api/charges/object#charge_object-outcome-network_status)
///
/// For Braintree, the outcome fields will be null. The code and message will contain one of
///   - a processor decline code (as a string) in code, and associated text in message, as defined
///     this [table](https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses)
///   - `gateway` in code, with a [reason](https://developer.paypal.com/braintree/articles/control-panel/transactions/gateway-rejections) in message
///   - `code` = "unknown", message = "unknown"
///
/// IAP payment processors will never include charge failure information, and detailed order
/// information should be retrieved from the payment processor directly.
public struct ChargeFailure: Sendable, Equatable {
    public var processor: PaymentProvider
    /// See [Stripe failure codes](https://stripe.com/docs/api/charges/object#charge_object-failure_code)
    /// or [Braintree decline codes](https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses#decline-codes)
    /// depending on which processor was used
    public var code: String
    /// See [Stripe failure codes](https://stripe.com/docs/api/charges/object#charge_object-failure_code)
    /// or [Braintree decline codes](https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses#decline-codes)
    /// depending on which processor was used
    public var message: String
    /// See [Outcome Network Status](https://stripe.com/docs/api/charges/object#charge_object-outcome-network_status)
    public var outcomeNetworkStatus: String?
    /// See [Outcome Reason](https://stripe.com/docs/api/charges/object#charge_object-outcome-reason)
    public var outcomeReason: String?
    /// See [Outcome Type](https://stripe.com/docs/api/charges/object#charge_object-outcome-type)
    public var outcomeType: String?

    public init(
        processor: PaymentProvider,
        code: String,
        message: String,
        outcomeNetworkStatus: String? = nil,
        outcomeReason: String? = nil,
        outcomeType: String? = nil
    ) {
        self.processor = processor
        self.code = code
        self.message = message
        self.outcomeNetworkStatus = outcomeNetworkStatus
        self.outcomeReason = outcomeReason
        self.outcomeType = outcomeType
    }
}

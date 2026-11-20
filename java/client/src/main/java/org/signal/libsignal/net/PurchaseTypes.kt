//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.io.IOException
import java.util.Objects
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

public sealed class PaymentProvider {
  public data object GooglePlayBilling : PaymentProvider()

  public data object AppleAppStore : PaymentProvider()

  public data object Stripe : PaymentProvider()

  public data object Braintree : PaymentProvider()
}

public sealed class PaymentMethod {
  public data object Card : PaymentMethod()

  public data object SepaDebit : PaymentMethod()

  public data object Ideal : PaymentMethod()

  public data object PayPal : PaymentMethod()

  public data object GooglePlayBilling : PaymentMethod()

  public data object AppleAppStore : PaymentMethod()
}

public data class PurchaseProductConfiguration(
  /** A map of lower-cased ISO 3 currency codes to currency-specific configuration */
  public val currencies: Map<String, CurrencyConfiguration>,
  /** A map of numeric donation level IDs to level-specific badge configuration */
  public val badgeLevels: Map<Long, BadgeLevelConfiguration>,
  /** Configuration for backup subscription options */
  public val backup: BackupConfiguration,
  /** Maximum value of a one-time SEPA donation, in EUR [minor units](https://docs.stripe.com/currencies#minor-units) */
  public val sepaMaximumEuros: Long,
  /** Configuration for one-time Signal Login purchases */
  public val login: LoginConfiguration,
) {
  public data class CurrencyConfiguration(
    /** Minimum one-time donation in the currency's [minor unit](https://docs.stripe.com/currencies#minor-units) */
    public val minimum: Long,
    /** Map of one-time donation level IDs to suggested amounts in the currency's minor unit */
    public val oneTimeDonationAmounts: Map<Long, LongArray>,
    /** Map of subscription level IDs to the amount charged in the currency's minor unit */
    public val subscriptionAmounts: Map<Long, Long>,
    /** Map of backup subscription level IDs to the amount charged in the currency's minor unit */
    public val backupSubscriptionAmounts: Map<Long, Long>,
    /**
     * List of payment methods that support this currency.
     *
     * Note that this list may be empty if the only supported payment methods are newer than what
     * this version of libsignal understands.
     */
    public val supportedPaymentMethods: List<PaymentMethod>,
  ) {
    public override fun equals(other: Any?): Boolean {
      if (other === this) return true
      if (other !is CurrencyConfiguration) return false
      if (minimum != other.minimum) return false
      if (subscriptionAmounts != other.subscriptionAmounts) return false
      if (backupSubscriptionAmounts != other.backupSubscriptionAmounts) return false
      if (supportedPaymentMethods != other.supportedPaymentMethods) return false
      if (oneTimeDonationAmounts.size != other.oneTimeDonationAmounts.size) return false
      return oneTimeDonationAmounts.all {
        val otherValue = other.oneTimeDonationAmounts.get(it.key)
        return otherValue != null && otherValue.contentEquals(it.value)
      }
    }

    public override fun hashCode(): Int =
      // Just omit the field that's difficult to hash -- that's still a valid hash.
      Objects.hash(minimum, subscriptionAmounts, backupSubscriptionAmounts, supportedPaymentMethods)
  }

  public data class BadgeLevelConfiguration(
    /**
     * The ID of the badge awarded at this level.
     *
     * Can be resolved to full badge details via [AuthRemoteConfigurationService.getBadges].
     */
    public val badgeId: String,
    /**
     * The duration for which a badge is valid.
     *
     * Present only for one-time badges (boosts and gifts).
     */
    public val badgeDuration: Duration?,
  ) {
    internal constructor(badgeId: String, badgeDurationSeconds: Int?) :
      this(badgeId, badgeDurationSeconds?.seconds) {}
  }

  public data class BackupConfiguration(
    /** A map of numeric backup level IDs to level-specific backup configuration */
    public val levels: Map<Long, BackupLevelConfiguration>,
    /** The number of days of media a free tier backup user gets */
    public val freeTierMediaDays: Int,
  )

  public data class BackupLevelConfiguration(
    /** The amount of media storage in bytes that a paying subscriber may store */
    public val storageAllowanceBytes: Long,
    /** The Play Store billing productID associated with this backup level */
    public val playProductId: String,
    /** The duration, in days, for which your backed up media is retained on the server after you stop refreshing with a paid credential */
    public val mediaTtlDays: Int,
  )

  public data class LoginConfiguration(
    /**
     * The receipt level associated with a Signal Login purchase.
     *
     * Should match your locally-expected level.
     */
    public val level: Long,
    /** The Play Store billing productID associated with a Signal Login purchase */
    public val playProductId: String,
    /** The Play Store billing optionID to use to purchase a Signal Login */
    public val playOptionId: String,
    /** The Apple App Store productID associated with a Signal Login purchase */
    public val appStoreProductId: String,
  )
}

public data class ChargeFailure(
  public val processor: PaymentProvider,
  public val code: String,
  public val message: String,
  public val outcomeNetworkStatus: String?,
  public val outcomeReason: String?,
  public val outcomeType: String?,
)

public sealed class ReceiptCredentialException(
  message: String,
) : IOException(message),
  BadRequestError {
  /**
   * The purchase is still pending with the payment provider. The client may retry later.
   *
   * See the specific request docs for more information.
   */
  public class PaymentStillProcessing : ReceiptCredentialException {
    @CalledFromNative
    public constructor(message: String) : super(message)
  }

  /**
   * The purchase did not complete successfully.
   */
  public class PaymentRequired : ReceiptCredentialException {
    public val chargeFailure: ChargeFailure?

    @CalledFromNative
    public constructor(message: String, chargeFailure: ChargeFailure?) : super(message) {
      this.chargeFailure = chargeFailure
    }
  }

  /**
   * The payment provider has no purchase with the provided identifier.
   *
   * See the specific request docs for more information.
   */
  public class PaymentNotFound : ReceiptCredentialException {
    @CalledFromNative
    public constructor(message: String) : super(message)
  }

  /**
   * The purchase was already redeemed for a receipt credential, but with a different receipt
   * credential request.
   */
  public class ReceiptAlreadyIssued : ReceiptCredentialException {
    @CalledFromNative
    public constructor(message: String) : super(message)
  }
}

//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.net

import org.signal.libsignal.internal.Native
import org.signal.libsignal.keytrans.Store
import org.signal.libsignal.protocol.ServiceId

public object KeyTransparency {
  /**
   * Mode of the key transparency operation.
   *
   * The behavior of [KeyTransparencyClient.check] differs depending on whether it is
   * performed for the owner of the account or contact and in the former case whether
   * the phone number discoverability is enabled.
   *
   * For example, if the newer version of account data is found in the key
   * transparency log while monitoring "self", it will terminate with an error.
   * However, the same check for a "contact" will result in a follow-up search
   * operation.
   */
  public sealed class CheckMode {
    public data class Self(
      val isE164Discoverable: Boolean,
    ) : CheckMode()

    public object Contact : CheckMode()

    public fun isE164Discoverable(): Boolean? =
      when (this) {
        is Self -> isE164Discoverable
        is Contact -> null
      }

    public fun isSelf(): Boolean = this is Self
  }

  /**
   * A tag identifying an optional field of the account data.
   *
   * (Must be in sync with the Rust counterpart)
   */
  public enum class AccountDataField(
    public val value: Int,
  ) {
    E164(0),
    USERNAME_HASH(1),
  }

  /**
   * Resets a particular field in the data associated with given ACI.
   *
   * Must only be called for the "self" account when either E.164 or username change is performed.
   *
   * Upon successful completion the data associated with the account will be updated in the store, if it
   * was present to begin with, noop if it was not.
   *
   * @param aci An ACI of "self" account.
   * @param field Account data field to be reset (E.164 or username hash)
   * @param store local persistent storage for key transparency-related data.
   * @throws IllegalArgumentException if the stored data cannot be decoded correctly, which means data corruption.
   */
  @JvmStatic
  public fun resetField(
    aci: ServiceId.Aci,
    field: AccountDataField,
    store: Store,
  ) {
    store.getAccountData(aci).map {
      val updated = Native.KeyTransparency_ResetDataField(it, field.value)
      if (updated.isEmpty()) {
        throw IllegalArgumentException("failed to decode account data")
      }
      store.setAccountData(aci, updated)
    }
  }
}

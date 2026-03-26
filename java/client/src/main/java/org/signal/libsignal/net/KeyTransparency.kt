//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.net

public abstract class KeyTransparency {
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
}

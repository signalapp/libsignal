//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import org.signal.libsignal.protocol.ServiceId
import java.io.IOException

/**
 * A failure sending to one or more recipients on account of not being up to date on their devices.
 *
 * Each entry in the exception represents a recipient that has either added, removed, or relinked
 * some devices in their account (potentially including their primary device), as represented by the
 * [Entry.missingDevices], [Entry.extraDevices], and [Entry.staleDevices] arrays, respectively.
 * Handling the exception involves removing the "extra" devices and establishing new sessions for
 * the "missing" and "stale" devices.
 */
public class MismatchedDeviceException :
  IOException,
  MultiRecipientSendFailure {
  public data class Entry(
    public val account: ServiceId,
    public val missingDevices: IntArray = intArrayOf(),
    public val extraDevices: IntArray = intArrayOf(),
    public val staleDevices: IntArray = intArrayOf(),
  ) {
    @CalledFromNative
    private constructor(
      rawAccount: ByteArray,
      missingDevices: IntArray,
      extraDevices: IntArray,
      staleDevices: IntArray,
    ) : this(ServiceId.parseFromFixedWidthBinary(rawAccount), missingDevices, extraDevices, staleDevices) {
    }

    // Unfortunately the default data class equals+hashCode use identity comparison for arrays.
    override fun equals(other: Any?): Boolean {
      if (other !is Entry) {
        return false
      }
      return account == other.account &&
        missingDevices.contentEquals(other.missingDevices) &&
        extraDevices.contentEquals(other.extraDevices) &&
        staleDevices.contentEquals(other.staleDevices)
    }

    override fun hashCode(): Int {
      var result = account.hashCode()
      result = 31 * result + missingDevices.contentHashCode()
      result = 31 * result + extraDevices.contentHashCode()
      result = 31 * result + staleDevices.contentHashCode()
      return result
    }
  }

  public val entries: Array<Entry>

  public constructor(message: String, entries: Array<Entry>) : super(message) {
    this.entries = entries
  }
}

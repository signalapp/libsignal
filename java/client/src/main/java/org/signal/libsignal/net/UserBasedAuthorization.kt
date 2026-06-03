//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken

public sealed class UserBasedAuthorization : UserBasedSendAuthorization {
  public data class AccessKey(
    val bytes: ByteArray,
  ) : UserBasedAuthorization() {
    // Because the default equals+hashCode compare based on identity, not value
    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (javaClass != other?.javaClass) return false

      other as AccessKey

      if (!bytes.contentEquals(other.bytes)) return false

      return true
    }

    override fun hashCode(): Int = bytes.contentHashCode()
  }

  public data class GroupSend(
    val token: GroupSendFullToken,
  ) : UserBasedAuthorization()

  public object UnrestrictedUnauthenticatedAccess : UserBasedAuthorization()
}

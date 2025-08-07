//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem

public enum class KEMKeyType(
  public val type: Int,
) {
  KYBER_1024(8),
}

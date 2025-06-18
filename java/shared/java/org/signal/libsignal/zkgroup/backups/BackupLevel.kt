//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.backups

public enum class BackupLevel {
  // This must match the Rust version of the enum.
  FREE(200),
  PAID(201),
  ;

  public val value: Int

  private constructor(value: Int) {
    this.value = value
  }

  public companion object {
    @JvmStatic
    public fun fromValue(value: Int): BackupLevel {
      // A linear scan is simpler than a hash lookup for a set of values this small.
      val found = BackupLevel.values().firstOrNull { it.value == value }
      return requireNotNull(found) { "Invalid backup level: $value" }
    }
  }
}

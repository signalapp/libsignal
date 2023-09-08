//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.protocol.kem;

public enum KEMKeyType {
  // Make sure to update KEMKeyPair.generate when adding new key types
  KYBER_1024(8);

  private final int type;

  private KEMKeyType(int type) {
    this.type = type;
  }
}

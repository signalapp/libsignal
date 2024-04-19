//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.backups;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum BackupLevel {
  // This must match the Rust version of the enum.
  MESSAGES(200),
  MEDIA(201);

  private static final Map<Integer, BackupLevel> LOOKUP =
      Arrays.stream(BackupLevel.values())
          .collect(Collectors.toMap(BackupLevel::getValue, Function.identity()));

  private final int value;

  BackupLevel(int value) {
    this.value = value;
  }

  int getValue() {
    return this.value;
  }

  public static BackupLevel fromValue(int value) {
    BackupLevel backupLevel = LOOKUP.get(value);
    if (backupLevel == null) {
      throw new IllegalArgumentException("Invalid backup level: " + value);
    }
    return backupLevel;
  }
}

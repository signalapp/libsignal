//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;

public class AccountEntropyPool {
  public static String generate() {
    return filterExceptions(() -> (Native.AccountEntropyPool_Generate()));
  }
}

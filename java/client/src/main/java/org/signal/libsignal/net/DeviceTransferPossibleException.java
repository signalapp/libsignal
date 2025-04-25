//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

public class DeviceTransferPossibleException extends RegistrationException {
  @CalledFromNative
  private DeviceTransferPossibleException(String message) {
    super(message);
  }
}

//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/** Indicates that the local device has been deregistered or delinked. */
public class DeviceDeregisteredException extends ChatServiceException {
  public DeviceDeregisteredException(String message) {
    super(message);
  }
}

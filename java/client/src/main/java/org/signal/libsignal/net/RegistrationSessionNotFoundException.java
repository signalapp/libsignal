//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * No session with the specified ID could be found.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 404} response to
 * requests to endpoints with the {@code /v1/verification/session} prefix.
 */
public class RegistrationSessionNotFoundException extends RegistrationException {
  @CalledFromNative
  public RegistrationSessionNotFoundException(String message) {
    super(message);
  }
}

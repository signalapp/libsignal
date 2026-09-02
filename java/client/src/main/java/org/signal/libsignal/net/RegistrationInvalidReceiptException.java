//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CalledFromNative;

/**
 * Thrown when the server does not accept the receipt credential presentation used to register.
 *
 * <p>The presentation failed verification, has expired, or has already been redeemed.
 *
 * <p>When the websocket transport is in use, this corresponds to a {@code HTTP 401} response to a
 * POST request to {@code /v1/registration} using receipt credential flow.
 */
public class RegistrationInvalidReceiptException extends RegistrationException {
  @CalledFromNative
  private RegistrationInvalidReceiptException(String message) {
    super(message);
  }
}

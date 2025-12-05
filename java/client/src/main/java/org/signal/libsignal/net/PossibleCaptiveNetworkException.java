//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/**
 * Indicates that a server presented a TLS certificate that might have come from a captive network.
 */
public class PossibleCaptiveNetworkException extends NetworkException {
  public PossibleCaptiveNetworkException(String message) {
    super(message);
  }
}

//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/** Error thrown when a CDSI server returns an unexpected response. */
public class CdsiProtocolException extends Exception {
  private CdsiProtocolException(String message) {
    super(message);
  }
}

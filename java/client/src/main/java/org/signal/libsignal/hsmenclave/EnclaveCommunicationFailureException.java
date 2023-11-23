//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.hsmenclave;

public class EnclaveCommunicationFailureException extends Exception {
  public EnclaveCommunicationFailureException(String msg) {
    super(msg);
  }

  public EnclaveCommunicationFailureException(Throwable t) {
    super(t);
  }
}

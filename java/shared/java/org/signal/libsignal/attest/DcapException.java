//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.attest;

public class DcapException extends Exception {
  public DcapException(String msg) {
    super(msg);
  }

  public DcapException(Throwable t) {
    super(t);
  }
}

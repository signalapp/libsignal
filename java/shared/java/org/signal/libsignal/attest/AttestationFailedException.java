//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.attest;

/** An enclave failed attestation. */
public class AttestationFailedException extends Exception {
  public AttestationFailedException(String msg) {
    super(msg);
  }

  public AttestationFailedException(Throwable t) {
    super(t);
  }
}

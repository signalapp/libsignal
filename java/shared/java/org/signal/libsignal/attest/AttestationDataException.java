//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.attest;

/** Attestation data was malformed. */
public class AttestationDataException extends Exception {
  public AttestationDataException(String msg) {
    super(msg);
  }

  public AttestationDataException(Throwable t) {
    super(t);
  }
}

//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.sgxsession;

/**
 * The communication channel with an enclave has failed.
 *
 * <p>Note that this affects non-SGX enclaves as well. It's named "SGX" for historical reasons.
 */
public class SgxCommunicationFailureException extends Exception {
  public SgxCommunicationFailureException(String msg) {
    super(msg);
  }

  public SgxCommunicationFailureException(Throwable t) {
    super(t);
  }
}

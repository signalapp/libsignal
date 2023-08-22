//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.svr2;

import java.time.Instant;
import org.signal.libsignal.attest.AttestationDataException;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.sgxsession.SgxClient;

/**
 * Svr2Client provides bindings to interact with Signal's v2 Secure Value Recovery service.
 *
 * <p>
 *
 * <p>{@inheritDoc}
 */
public class Svr2Client extends SgxClient {
  public Svr2Client(byte[] mrenclave, byte[] attestationMsg, Instant currentInstant)
      throws AttestationDataException {
    super(Native.Svr2Client_New(mrenclave, attestationMsg, currentInstant.toEpochMilli()));
  }
}

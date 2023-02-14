//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.cds2;

import org.signal.libsignal.sgxsession.SgxClient;
import org.signal.libsignal.attest.AttestationDataException;
import org.signal.libsignal.internal.Native;

import java.time.Instant;

/**
 * Cds2Client provides bindings to interact with Signal's v2 Contact Discovery Service. <p>
 *
 * {@inheritDoc}
 *
 * A future update to Cds2Client will implement additional parts of the contact discovery protocol.
 */
public class Cds2Client extends SgxClient {
  public Cds2Client(byte[] mrenclave, byte[] attestationMsg, Instant currentInstant) throws AttestationDataException {
    super(Native.Cds2ClientState_New(mrenclave, attestationMsg, currentInstant.toEpochMilli()));
  }
}

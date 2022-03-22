/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.fingerprint;

import org.signal.libsignal.protocol.IdentityKey;

import java.util.List;

public interface FingerprintGenerator {
  public Fingerprint createFor(int version,
                               byte[] localStableIdentifier,
                               IdentityKey localIdentityKey,
                               byte[] remoteStableIdentifier,
                               IdentityKey remoteIdentityKey);

}

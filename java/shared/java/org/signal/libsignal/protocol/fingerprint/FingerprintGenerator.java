//
// Copyright 2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.fingerprint;

import org.signal.libsignal.protocol.IdentityKey;

public interface FingerprintGenerator {
  public Fingerprint createFor(
      int version,
      byte[] localStableIdentifier,
      IdentityKey localIdentityKey,
      byte[] remoteStableIdentifier,
      IdentityKey remoteIdentityKey);
}

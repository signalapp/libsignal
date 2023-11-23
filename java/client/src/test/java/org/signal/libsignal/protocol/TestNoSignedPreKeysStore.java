//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import org.signal.libsignal.protocol.state.SignedPreKeyRecord;

public class TestNoSignedPreKeysStore extends TestInMemorySignalProtocolStore {
  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    throw new InvalidKeyIdException("TestNoSignedPreKeysStore rejected loading " + signedPreKeyId);
  }
}

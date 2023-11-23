//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import org.signal.libsignal.protocol.state.SignedPreKeyRecord;

public class TestBadSignedPreKeysStore extends TestInMemorySignalProtocolStore {
  public static class CustomException extends RuntimeException {
    CustomException(String message) {
      super(message);
    }
  }

  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    throw new CustomException("TestBadSignedPreKeysStore rejected loading " + signedPreKeyId);
  }
}

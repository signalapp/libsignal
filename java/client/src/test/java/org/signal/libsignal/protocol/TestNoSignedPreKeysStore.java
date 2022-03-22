package org.signal.libsignal.protocol;

import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;

public class TestNoSignedPreKeysStore extends TestInMemorySignalProtocolStore {
  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    throw new InvalidKeyIdException("TestNoSignedPreKeysStore rejected loading " + signedPreKeyId);
  }
}

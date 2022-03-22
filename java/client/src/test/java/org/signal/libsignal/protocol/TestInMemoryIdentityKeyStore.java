package org.signal.libsignal.protocol;

import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.util.KeyHelper;

public class TestInMemoryIdentityKeyStore extends org.signal.libsignal.protocol.state.impl.InMemoryIdentityKeyStore {
  public TestInMemoryIdentityKeyStore() {
    super(generateIdentityKeyPair(), generateRegistrationId());
  }

  private static IdentityKeyPair generateIdentityKeyPair() {
    ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

    return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                               identityKeyPairKeys.getPrivateKey());
  }

  private static int generateRegistrationId() {
    return KeyHelper.generateRegistrationId(false);
  }

}

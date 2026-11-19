//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import java.util.ArrayList;
import java.util.List;
import kotlin.Pair;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore;
import org.signal.libsignal.protocol.util.KeyHelper;

public class TestInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
  public final List<Pair<SignalProtocolAddress, IdentityKey>> receivedIdentities =
      new ArrayList<>();

  public TestInMemorySignalProtocolStore() {
    super(generateIdentityKeyPair(), generateRegistrationId());
  }

  @Override
  public void recordReceivedIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
    super.recordReceivedIdentity(address, identityKey);
    receivedIdentities.add(new Pair<>(address, identityKey));
  }

  private static IdentityKeyPair generateIdentityKeyPair() {
    ECKeyPair identityKeyPairKeys = ECKeyPair.generate();

    return new IdentityKeyPair(
        new IdentityKey(identityKeyPairKeys.getPublicKey()), identityKeyPairKeys.getPrivateKey());
  }

  private static int generateRegistrationId() {
    return KeyHelper.generateRegistrationId(false);
  }
}

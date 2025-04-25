//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.junit.Assert.*;

import org.junit.Test;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.impl.InMemoryIdentityKeyStore;

public class IdentityKeyStoreTest {
  @Test
  public void testInMemoryIdentityKeyStore() {
    IdentityKeyPair identity = IdentityKeyPair.generate();
    int localRegistrationId = 23;

    IdentityKeyStore store = new InMemoryIdentityKeyStore(identity, localRegistrationId);

    var address = new SignalProtocolAddress("address", 12);
    assertEquals(null, store.getIdentity(address));

    IdentityKey firstIdentity = IdentityKeyPair.generate().getPublicKey();
    assertTrue(store.isTrustedIdentity(address, firstIdentity, IdentityKeyStore.Direction.SENDING));

    assertEquals(
        IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED,
        store.saveIdentity(address, firstIdentity));
    // Idempotent
    assertEquals(
        IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED,
        store.saveIdentity(address, firstIdentity));
    assertTrue(store.isTrustedIdentity(address, firstIdentity, IdentityKeyStore.Direction.SENDING));
    assertEquals(firstIdentity, store.getIdentity(address));

    IdentityKey secondIdentity = IdentityKeyPair.generate().getPublicKey();

    assertFalse(
        store.isTrustedIdentity(address, secondIdentity, IdentityKeyStore.Direction.SENDING));
    assertEquals(
        IdentityKeyStore.IdentityChange.REPLACED_EXISTING,
        store.saveIdentity(address, secondIdentity));
    // Idempotent
    assertEquals(
        IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED,
        store.saveIdentity(address, secondIdentity));

    assertTrue(
        store.isTrustedIdentity(address, secondIdentity, IdentityKeyStore.Direction.SENDING));
    assertEquals(secondIdentity, store.getIdentity(address));
  }
}

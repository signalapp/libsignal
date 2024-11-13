//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;
import static org.signal.libsignal.net.KeyTransparencyTest.TEST_ACI;
import static org.signal.libsignal.net.KeyTransparencyTest.TEST_ACI_IDENTITY_KEY;

import org.junit.Assume;
import org.junit.Test;
import org.signal.libsignal.keytrans.SearchResult;
import org.signal.libsignal.keytrans.TestStore;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.util.TestEnvironment;

public class KeyTransparencyClientTest {
  private static final String USER_AGENT = "test";
  private static final boolean INTEGRATION_TESTS_ENABLED =
      TestEnvironment.get("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS") != null;

  @Test
  public void searchInStagingIntegration() throws Exception {
    Assume.assumeTrue(INTEGRATION_TESTS_ENABLED);

    final Network net = new Network(Network.Environment.STAGING, USER_AGENT);
    final UnauthenticatedChatService chat = net.createUnauthChatService(null);
    chat.connect().get();

    TestStore store = new TestStore();

    SearchResult result =
        chat.keyTransparencyClient()
            .search(
                TEST_ACI,
                TEST_ACI_IDENTITY_KEY,
                "+18005550100",
                Hex.fromStringCondensedAssert("fdc7951d1507268daf1834b74d23b76c"),
                null,
                store)
            .get();

    assertTrue(store.getLastDistinguishedTreeHead().isPresent());
    assertTrue(store.getLastTreeHead().isPresent());
    assertEquals(
        "05d0e797ec91a4bce0e88959c419e96eb4fdabbb3dc688965584c966dc24195609",
        Hex.toStringCondensed(result.getAciIdentityKey().serialize()));
    assertTrue(result.getAciForE164().isPresent());
    assertEquals(TEST_ACI, result.getAciForE164().get());
  }

  @Test
  public void updateDistinguishedStagingIntegration() throws Exception {
    Assume.assumeTrue(INTEGRATION_TESTS_ENABLED);

    final Network net = new Network(Network.Environment.STAGING, USER_AGENT);
    final UnauthenticatedChatService chat = net.createUnauthChatService(null);
    chat.connect().get();

    TestStore store = new TestStore();
    chat.keyTransparencyClient().updateDistinguished(store).get();

    assertTrue(store.getLastDistinguishedTreeHead().isPresent());
  }
}

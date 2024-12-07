//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;
import static org.signal.libsignal.net.KeyTransparencyTest.TEST_ACI;
import static org.signal.libsignal.net.KeyTransparencyTest.TEST_ACI_IDENTITY_KEY;
import static org.signal.libsignal.net.KeyTransparencyTest.TEST_E164;
import static org.signal.libsignal.net.KeyTransparencyTest.TEST_UNIDENTIFIED_ACCESS_KEY;
import static org.signal.libsignal.net.KeyTransparencyTest.TEST_USERNAME_HASH;

import java.util.Deque;
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
                TEST_E164,
                TEST_UNIDENTIFIED_ACCESS_KEY,
                TEST_USERNAME_HASH,
                store)
            .get();

    assertTrue(store.getLastDistinguishedTreeHead().isPresent());
    assertTrue(store.getAccountData(TEST_ACI).isPresent());
    assertEquals(
        "05d0e797ec91a4bce0e88959c419e96eb4fdabbb3dc688965584c966dc24195609",
        Hex.toStringCondensed(result.getAciIdentityKey().serialize()));
    assertTrue(result.getAciForE164().isPresent());
    assertEquals(TEST_ACI, result.getAciForE164().get());
    assertTrue(result.getAciForUsernameHash().isPresent());
    assertEquals(TEST_ACI, result.getAciForUsernameHash().get());
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

  @Test
  public void monitorInStagingIntegration() throws Exception {
    Assume.assumeTrue(INTEGRATION_TESTS_ENABLED);

    final Network net = new Network(Network.Environment.STAGING, USER_AGENT);
    final UnauthenticatedChatService chat = net.createUnauthChatService(null);
    chat.connect().get();

    TestStore store = new TestStore();

    SearchResult ignoredSearchResult =
        chat.keyTransparencyClient()
            .search(
                TEST_ACI,
                TEST_ACI_IDENTITY_KEY,
                TEST_E164,
                TEST_UNIDENTIFIED_ACCESS_KEY,
                TEST_USERNAME_HASH,
                store)
            .get();

    Deque<byte[]> accountDataHistory = store.storage.get(TEST_ACI);

    // Following search there should be a single entry in the account history
    assertEquals(1, accountDataHistory.size());

    chat.keyTransparencyClient().monitor(TEST_ACI, TEST_E164, TEST_USERNAME_HASH, store).get();
    // Another entry in the account history after a successful monitor request
    assertEquals(2, accountDataHistory.size());
  }
}

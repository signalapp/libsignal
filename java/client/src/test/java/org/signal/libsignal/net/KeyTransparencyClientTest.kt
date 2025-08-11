//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.net

import org.junit.Assert
import org.junit.Assume
import org.junit.Test
import org.signal.libsignal.keytrans.KeyTransparencyException
import org.signal.libsignal.keytrans.TestStore
import org.signal.libsignal.net.KeyTransparency.MonitorMode
import org.signal.libsignal.util.TestEnvironment
import java.util.Deque
import java.util.concurrent.ExecutionException

class KeyTransparencyClientTest {
  fun connectAndGetClient(net: Network) =
    net
      .connectUnauthChat(null)
      .thenApply {
        it!!.start()
        it.keyTransparencyClient()
      }

  @Test
  @Throws(Exception::class)
  fun searchInStagingIntegration() {
    Assume.assumeTrue(INTEGRATION_TESTS_ENABLED)

    val net = Network(Network.Environment.STAGING, USER_AGENT)
    val ktClient = connectAndGetClient(net).get()

    val store = TestStore()

    ktClient
      .search(
        KeyTransparencyTest.TEST_ACI,
        KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
        KeyTransparencyTest.TEST_E164,
        KeyTransparencyTest.TEST_UNIDENTIFIED_ACCESS_KEY,
        KeyTransparencyTest.TEST_USERNAME_HASH,
        store,
      ).get()

    Assert.assertTrue(store.getLastDistinguishedTreeHead().isPresent)
    Assert.assertTrue(store.getAccountData(KeyTransparencyTest.TEST_ACI).isPresent)
  }

  @Test
  @Throws(Exception::class)
  fun updateDistinguishedStagingIntegration() {
    Assume.assumeTrue(INTEGRATION_TESTS_ENABLED)

    val net = Network(Network.Environment.STAGING, USER_AGENT)
    val ktClient = connectAndGetClient(net).get()

    val store = TestStore()
    ktClient.updateDistinguished(store).get()

    Assert.assertTrue(store.getLastDistinguishedTreeHead().isPresent)
  }

  @Test
  @Throws(Exception::class)
  fun monitorInStagingIntegration() {
    Assume.assumeTrue(INTEGRATION_TESTS_ENABLED)

    val net = Network(Network.Environment.STAGING, USER_AGENT)
    val ktClient = connectAndGetClient(net).get()

    val store = TestStore()

    ktClient
      .search(
        KeyTransparencyTest.TEST_ACI,
        KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
        KeyTransparencyTest.TEST_E164,
        KeyTransparencyTest.TEST_UNIDENTIFIED_ACCESS_KEY,
        KeyTransparencyTest.TEST_USERNAME_HASH,
        store,
      ).get()

    val accountDataHistory: Deque<ByteArray?> = store.storage.get(KeyTransparencyTest.TEST_ACI)!!

    // Following search there should be a single entry in the account history
    Assert.assertEquals(1, accountDataHistory.size.toLong())

    ktClient
      .monitor(
        MonitorMode.SELF,
        KeyTransparencyTest.TEST_ACI,
        KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
        KeyTransparencyTest.TEST_E164,
        KeyTransparencyTest.TEST_UNIDENTIFIED_ACCESS_KEY,
        KeyTransparencyTest.TEST_USERNAME_HASH,
        store,
      ).get()
    // Another entry in the account history after a successful monitor request
    Assert.assertEquals(2, accountDataHistory.size.toLong())
  }

  @Test
  @Throws(Exception::class)
  fun monitorNoDataInStore() {
    Assume.assumeTrue(INTEGRATION_TESTS_ENABLED)

    val net = Network(Network.Environment.STAGING, USER_AGENT)
    val ktClient = connectAndGetClient(net).get()

    val store = TestStore()

    // Call to monitor before any data has been persisted in the store.
    // Distinguished tree will be requested from the server, but it will fail
    // due to account data missing.
    try {
      ktClient
        .monitor(
          MonitorMode.SELF,
          KeyTransparencyTest.TEST_ACI,
          KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
          KeyTransparencyTest.TEST_E164,
          KeyTransparencyTest.TEST_UNIDENTIFIED_ACCESS_KEY,
          KeyTransparencyTest.TEST_USERNAME_HASH,
          store,
        ).get()
    } catch (e: ExecutionException) {
      Assert.assertTrue(e.cause is KeyTransparencyException)
    }
  }

  companion object {
    private const val USER_AGENT = "test"
    private val INTEGRATION_TESTS_ENABLED = TestEnvironment.get("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS") != null
  }
}

//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.net

import org.junit.Assert
import org.junit.Assume
import org.junit.Test
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.keytrans.KeyTransparencyException
import org.signal.libsignal.keytrans.TestStore
import org.signal.libsignal.net.KeyTransparency.MonitorMode
import org.signal.libsignal.util.TestEnvironment
import java.util.Deque
import java.util.concurrent.ExecutionException
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

private fun <T> retryImpl(
  n: Int,
  makeFuture: () -> CompletableFuture<T>,
  isRetriable: (e: Throwable) -> Boolean,
): CompletableFuture<T> {
  for (i in n downTo 1) {
    try {
      return CompletableFuture.completedFuture(makeFuture().get())
    } catch (e: ExecutionException) {
      if (!isRetriable(e) || i == 1) {
        return CompletableFuture.failedFuture<T>(e.cause)
      }
      println("Retrying. Tries left ${i - 1}...")
    }
  }
  error("Future retry logic failed")
}

class KeyTransparencyClientTest {
  fun connectAndGetClient(net: Network): CompletableFuture<KeyTransparencyClient> {
    val retryConnect = retryImpl(3, { net.connectUnauthChat(null) }, { it.cause is ChatServiceException })
    return retryConnect
      .thenApply {
        it!!.start()
        it.keyTransparencyClient()
      }
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

  inline fun <reified E> networkExceptionsTestImpl(
    statusCode: Int,
    message: String = "",
    headers: Array<String> = arrayOf(),
  ) {
    val tokio = TokioAsyncContext()
    val chatAndFakeRemote =
      UnauthenticatedChatConnection.fakeConnect(
        tokio,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val chat = chatAndFakeRemote.first()
    val remote = chatAndFakeRemote.second()

    val store = TestStore()
    val responseFuture = chat.keyTransparencyClient().updateDistinguished(store)

    val requestId = remote.getNextIncomingRequest().get().second()
    remote.sendResponse(requestId, statusCode, message, headers, byteArrayOf())

    val exception = assertFailsWith<ExecutionException> { responseFuture.get() }
    assertIs<E>(exception.cause)
  }

  @Test
  @Throws(ExecutionException::class, InterruptedException::class)
  fun networkExceptions() {
    networkExceptionsTestImpl<RetryLaterException>(429, headers = arrayOf("retry-after: 42"))
    networkExceptionsTestImpl<ServerSideErrorException>(500)
    // 429 without the retry-after is unexpected
    networkExceptionsTestImpl<UnexpectedResponseException>(429)
  }

  companion object {
    private const val USER_AGENT = "test"
    private val INTEGRATION_TESTS_ENABLED =
      TestEnvironment.get("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS") != null &&
        TestEnvironment.get("LIBSIGNAL_TESTING_IGNORE_KT_TESTS") == null
  }
}

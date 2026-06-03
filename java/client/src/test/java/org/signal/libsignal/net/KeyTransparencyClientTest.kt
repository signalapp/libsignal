//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.net

import org.junit.Assert
import org.junit.Assume
import org.junit.Test
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeTesting
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.keytrans.TestStore
import org.signal.libsignal.net.KeyTransparency.CheckMode
import org.signal.libsignal.util.TestEnvironment
import java.util.Deque
import java.util.concurrent.ExecutionException
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

    val net = Network(Network.Environment.STAGING, USER_AGENT, mapOf(), Network.BuildVariant.BETA)
    val ktClient = connectAndGetClient(net).get()

    val store = TestStore()

    // No data in store will trigger a search
    ktClient
      .check(
        CheckMode.Contact,
        KeyTransparencyTest.TEST_ACI,
        KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
        KeyTransparencyTest.TEST_E164,
        KeyTransparencyTest.TEST_UNIDENTIFIED_ACCESS_KEY,
        KeyTransparencyTest.TEST_USERNAME_HASH,
        store,
      ).get()
      .also {
        assertIs<RequestResult.Success<*>>(it)
      }

    Assert.assertTrue(store.lastDistinguishedTreeHead.isPresent)
    Assert.assertTrue(store.getAccountData(KeyTransparencyTest.TEST_ACI).isPresent)
  }

  @Test
  @Throws(Exception::class)
  fun monitorInStagingIntegration() {
    Assume.assumeTrue(INTEGRATION_TESTS_ENABLED)

    val net = Network(Network.Environment.STAGING, USER_AGENT, mapOf(), Network.BuildVariant.BETA)
    val ktClient = connectAndGetClient(net).get()

    val store = TestStore()

    ktClient
      .check(
        CheckMode.Contact,
        KeyTransparencyTest.TEST_ACI,
        KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
        KeyTransparencyTest.TEST_E164,
        KeyTransparencyTest.TEST_UNIDENTIFIED_ACCESS_KEY,
        KeyTransparencyTest.TEST_USERNAME_HASH,
        store,
      ).get()
      .also {
        assertIs<RequestResult.Success<*>>(it)
      }

    val accountDataHistory: Deque<ByteArray?> = store.storage.get(KeyTransparencyTest.TEST_ACI)!!

    // Following search there should be a single entry in the account history
    Assert.assertEquals(1, accountDataHistory.size.toLong())
    // Should have requested and stored the latest distinguished tree head
    Assert.assertEquals(1, store.distinguishedTreeHeads.size)

    ktClient
      .check(
        CheckMode.Contact,
        KeyTransparencyTest.TEST_ACI,
        KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
        KeyTransparencyTest.TEST_E164,
        KeyTransparencyTest.TEST_UNIDENTIFIED_ACCESS_KEY,
        KeyTransparencyTest.TEST_USERNAME_HASH,
        store,
      ).get()
      .also {
        assertIs<RequestResult.Success<*>>(it)
      }
    // Another entry in the account history after a successful monitor request
    Assert.assertEquals(2, accountDataHistory.size.toLong())
    // Should not have updated the distinguished tree head, as the last one was reused
    Assert.assertEquals(1, store.distinguishedTreeHeads.size)
  }

  inline fun <reified E : Throwable> retryableNetworkExceptionsTestImpl(
    statusCode: Int,
    message: String = "",
    headers: Array<String> = arrayOf(),
  ) {
    val tokio = TokioAsyncContext()
    val (chat, remote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokio,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val store = TestStore()
    val responseFuture =
      chat
        .keyTransparencyClient()
        .check(
          CheckMode.Contact,
          KeyTransparencyTest.TEST_ACI,
          KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
          null,
          null,
          null,
          store,
        )

    val (_, requestId) = remote.nextIncomingRequest.get()
    remote.sendResponse(requestId, statusCode, message, headers, byteArrayOf())

    val result = responseFuture.get()
    val retryable = assertIs<RequestResult.RetryableNetworkError>(result)
    assertIs<E>(retryable.networkError)
  }

  inline fun <reified E : Throwable> applicationErrorTestImpl(
    statusCode: Int,
    message: String = "",
    headers: Array<String> = arrayOf(),
  ) {
    val tokio = TokioAsyncContext()
    val (chat, remote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokio,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val store = TestStore()
    val responseFuture =
      chat
        .keyTransparencyClient()
        .check(
          CheckMode.Contact,
          KeyTransparencyTest.TEST_ACI,
          KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
          null,
          null,
          null,
          store,
        )

    val (_, requestId) = remote.nextIncomingRequest.get()
    remote.sendResponse(requestId, statusCode, message, headers, byteArrayOf())

    val result = responseFuture.get()
    val appError = assertIs<RequestResult.ApplicationError>(result)
    assertIs<E>(appError.cause)
  }

  fun chatServiceInactiveIsRetryableNetworkErrorTestImpl() {
    val tokio = TokioAsyncContext()
    val (chat, remote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokio,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val store = TestStore()
    val responseFuture =
      chat
        .keyTransparencyClient()
        .check(
          CheckMode.Contact,
          KeyTransparencyTest.TEST_ACI,
          KeyTransparencyTest.TEST_ACI_IDENTITY_KEY,
          null,
          null,
          null,
          store,
        )

    remote.nextIncomingRequest.get()
    remote.guardedRun(NativeTesting::TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted)

    val result = responseFuture.get()
    val retryable = assertIs<RequestResult.RetryableNetworkError>(result)
    assertIs<ChatServiceInactiveException>(retryable.networkError)
  }

  @Test
  @Throws(ExecutionException::class, InterruptedException::class)
  fun networkExceptions() {
    chatServiceInactiveIsRetryableNetworkErrorTestImpl()
    retryableNetworkExceptionsTestImpl<RetryLaterException>(429, headers = arrayOf("retry-after: 42"))
    retryableNetworkExceptionsTestImpl<ServerSideErrorException>(500)
    // 429 without the retry-after is unexpected
    applicationErrorTestImpl<UnexpectedResponseException>(429)
  }

  companion object {
    private const val USER_AGENT = "test"
    private val INTEGRATION_TESTS_ENABLED =
      TestEnvironment.get("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS") != null &&
        TestEnvironment.get("LIBSIGNAL_TESTING_IGNORE_KT_TESTS") == null
  }
}

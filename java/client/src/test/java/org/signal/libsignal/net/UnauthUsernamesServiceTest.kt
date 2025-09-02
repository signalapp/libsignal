//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.junit.Assert.assertEquals
import org.junit.Test
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.protocol.ServiceId.Aci
import org.signal.libsignal.util.Base64
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlin.test.assertIs

class UnauthUsernamesServiceTest {
  @Test
  fun testLookupUsernameHashSuccess() {
    val tokioAsyncContext = TokioAsyncContext()
    val chatAndFakeRemote =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val chat = chatAndFakeRemote.first()
    val fakeRemote = chatAndFakeRemote.second()

    val accountsService = UnauthUsernamesService(chat)
    val testHash = byteArrayOf(1, 2, 3, 4)
    val responseFuture = accountsService.lookUpUsernameHash(testHash)

    // Get the incoming request from the fake remote
    val requestAndId = fakeRemote.getNextIncomingRequest().get()
    val request = requestAndId.first()
    val requestId = requestAndId.second()

    assertEquals("GET", request.method)
    val expectedPath = "/v1/accounts/username_hash/" + Base64.encodeToStringUrl(testHash)
    assertEquals(expectedPath, request.pathAndQuery)

    // Send successful response with UUID
    val uuid = UUID.fromString("4FCFE887-A600-40CD-9AB7-FD2A695E9981")
    val jsonResponse =
      """
      {
        "uuid": "$uuid"
      }
      """.trimIndent()

    fakeRemote.sendResponse(
      requestId,
      200,
      "OK",
      arrayOf("content-type: application/json"),
      jsonResponse.toByteArray(StandardCharsets.UTF_8),
    )

    // Verify the result
    val result = responseFuture.get()
    val successResult = assertIs<RequestResult.Success<Aci?>>(result)
    assertEquals(Aci(uuid), successResult.result)
  }

  @Test
  fun testLookupUsernameHashNotFound() {
    val tokioAsyncContext = TokioAsyncContext()
    val chatAndFakeRemote =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val chat = chatAndFakeRemote.first()
    val fakeRemote = chatAndFakeRemote.second()

    val accountsService = UnauthUsernamesService(chat)
    val testHash = byteArrayOf(1, 2, 3, 4)
    val responseFuture = accountsService.lookUpUsernameHash(testHash)

    // Get the incoming request from the fake remote
    val requestAndId = fakeRemote.getNextIncomingRequest().get()
    val request = requestAndId.first()
    val requestId = requestAndId.second()

    assertEquals("GET", request.method)
    val expectedPath = "/v1/accounts/username_hash/" + Base64.encodeToStringUrl(testHash)
    assertEquals(expectedPath, request.pathAndQuery)

    // Send fake 404 response (user not found)
    fakeRemote.sendResponse(
      requestId,
      404,
      "Not Found",
      arrayOf(),
      byteArrayOf(),
    )

    // Verify the result
    val result = responseFuture.get()
    val successResult = assertIs<RequestResult.Success<Aci?>>(result)
    assertEquals(null, successResult.result)
  }

  @Test
  fun testLookupUsernameHashRetryLater() {
    val tokioAsyncContext = TokioAsyncContext()
    val chatAndFakeRemote =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val chat = chatAndFakeRemote.first()
    val fakeRemote = chatAndFakeRemote.second()

    val accountsService = UnauthUsernamesService(chat)
    val testHash = byteArrayOf(1, 2, 3, 4)
    val responseFuture = accountsService.lookUpUsernameHash(testHash)

    // Get the incoming request from the fake remote
    val requestAndId = fakeRemote.getNextIncomingRequest().get()
    val request = requestAndId.first()
    val requestId = requestAndId.second()

    assertEquals("GET", request.method)

    // Send 429 response to trigger RetryLater
    fakeRemote.sendResponse(
      requestId,
      429,
      "Too Many Requests",
      arrayOf("retry-after: 120"),
      byteArrayOf(),
    )

    // Verify the result
    val result = responseFuture.get()
    val retryLater = assertIs<RequestResult.RetryableNetworkError>(result)
    assertEquals(120L, retryLater.retryAfter?.seconds)
  }

  @Test
  fun testLookupUsernameHashTransportError() {
    val tokioAsyncContext = TokioAsyncContext()
    val chatAndFakeRemote =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )
    val chat = chatAndFakeRemote.first()
    val fakeRemote = chatAndFakeRemote.second()

    val accountsService = UnauthUsernamesService(chat)
    val testHash = byteArrayOf(1, 2, 3, 4)
    val responseFuture = accountsService.lookUpUsernameHash(testHash)

    // Get the incoming request from the fake remote
    val requestAndId = fakeRemote.getNextIncomingRequest().get()
    val request = requestAndId.first()
    val requestId = requestAndId.second()

    assertEquals("GET", request.method)

    // Send server error response
    fakeRemote.sendResponse(
      requestId,
      500,
      "Internal Server Error",
      arrayOf(),
      byteArrayOf(),
    )

    // Verify the result
    val result = responseFuture.get()
    val retryableNetworkError = assertIs<RequestResult.RetryableNetworkError>(result)
    assertIs<ServerSideErrorException>(retryableNetworkError.networkError)
  }
}

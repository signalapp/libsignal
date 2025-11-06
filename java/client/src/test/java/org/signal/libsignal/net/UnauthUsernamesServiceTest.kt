//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.protocol.ServiceId.Aci
import org.signal.libsignal.protocol.util.Hex
import org.signal.libsignal.usernames.Username
import org.signal.libsignal.usernames.UsernameLinkInvalidEntropyDataLength
import org.signal.libsignal.usernames.UsernameLinkInvalidLinkData
import org.signal.libsignal.util.Base64
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlin.test.assertIs

class UnauthUsernamesServiceTest {
  companion object {
    val EXPECTED_USERNAME = "moxie.01"
    val ENCRYPTED_USERNAME =
      "kj5ah-VbEgjpfJsNt-Wto2H626DRmJSVpYPy0yPOXA8kiSFkBCD8ysFlJ-Z3MhiAnt_R3Nm7ZY0W5fiRDLVbhaE2z-KO2xdf5NcVbkewCzhvveecS3hHskDp1aSfbvwTZNNGPmAuKWvJ1MPdHzsF0w"
    val ENCRYPTED_USERNAME_ENTROPY =
      Hex.fromStringCondensedAssert(
        "4302c613c092a51c5394becffeb6f697300a605348e93f03c3db95e0b03d28f1",
      )
  }

  @Test
  fun testLookupUsernameHashSuccess() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val testHash = byteArrayOf(1, 2, 3, 4)
    val responseFuture = accountsService.lookUpUsernameHash(testHash)

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

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
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val testHash = byteArrayOf(1, 2, 3, 4)
    val responseFuture = accountsService.lookUpUsernameHash(testHash)

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

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
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val testHash = byteArrayOf(1, 2, 3, 4)
    val responseFuture = accountsService.lookUpUsernameHash(testHash)

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

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
  fun testLookupUsernameHashServerError() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val testHash = byteArrayOf(1, 2, 3, 4)
    val responseFuture = accountsService.lookUpUsernameHash(testHash)

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

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

  @Test
  fun testLookupUsernameLinkSuccess() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val responseFuture = accountsService.lookUpUsernameLink(UUID(0, 0), ENCRYPTED_USERNAME_ENTROPY)

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

    assertEquals("GET", request.method)
    assertEquals("/v1/accounts/username_link/00000000-0000-0000-0000-000000000000", request.pathAndQuery)

    // Send successful response
    val jsonResponse =
      """
      {
        "usernameLinkEncryptedValue": "$ENCRYPTED_USERNAME"
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
    val successResult = assertIs<RequestResult.Success<Username?>>(result)
    assertNotNull(successResult.result)
    assertEquals(EXPECTED_USERNAME, successResult.result!!.username)
  }

  @Test
  fun testLookupUsernameLinkNotFound() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val responseFuture = accountsService.lookUpUsernameLink(UUID(0, 0), ENCRYPTED_USERNAME_ENTROPY)

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

    assertEquals("GET", request.method)
    assertEquals("/v1/accounts/username_link/00000000-0000-0000-0000-000000000000", request.pathAndQuery)

    // Send fake 404 response (link not found)
    fakeRemote.sendResponse(
      requestId,
      404,
      "Not Found",
      arrayOf(),
      byteArrayOf(),
    )

    // Verify the result
    val result = responseFuture.get()
    val successResult = assertIs<RequestResult.Success<Username?>>(result)
    assertEquals(null, successResult.result)
  }

  @Test
  fun testLookupUsernameLinkGarbageCiphertext() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val responseFuture = accountsService.lookUpUsernameLink(UUID(0, 0), ENCRYPTED_USERNAME_ENTROPY)

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

    assertEquals("GET", request.method)
    assertEquals("/v1/accounts/username_link/00000000-0000-0000-0000-000000000000", request.pathAndQuery)

    // Send successful response
    val jsonResponse =
      """
      {
        "usernameLinkEncryptedValue": "${ENCRYPTED_USERNAME}A"
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
    val failureResult = assertIs<RequestResult.NonSuccess<LookUpUsernameLinkFailure>>(result)
    assertIs<UsernameLinkInvalidLinkData>(failureResult.error)
  }

  @Test
  fun testLookupUsernameLinkServerError() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val responseFuture = accountsService.lookUpUsernameLink(UUID(0, 0), ENCRYPTED_USERNAME_ENTROPY)

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

    assertEquals("GET", request.method)
    assertEquals("/v1/accounts/username_link/00000000-0000-0000-0000-000000000000", request.pathAndQuery)

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

  @Test
  fun testLookupUsernameLinkBadEntropy() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val accountsService = UnauthUsernamesService(chat)
    val responseFuture =
      accountsService.lookUpUsernameLink(
        UUID(0, 0),
        ENCRYPTED_USERNAME_ENTROPY.copyOf(
          ENCRYPTED_USERNAME_ENTROPY.count() - 1,
        ),
      )

    val result = responseFuture.get()
    val failureResult = assertIs<RequestResult.NonSuccess<LookUpUsernameLinkFailure>>(result)
    assertIs<UsernameLinkInvalidEntropyDataLength>(failureResult.error)
  }
}

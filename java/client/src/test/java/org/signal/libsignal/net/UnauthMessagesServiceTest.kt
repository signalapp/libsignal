//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.protocol.ServiceId.Aci
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.Future
import kotlin.test.assertIs

class UnauthMessagesServiceTest {
  private fun sendTestMultiRecipientMessage(
    chat: UnauthenticatedChatConnection,
    fakeRemote: FakeChatRemote,
  ): Pair<Future<RequestResult<MultiRecipientMessageResponse, MultiRecipientSendFailure>>, Long> {
    val messagesService = UnauthMessagesService(chat)

    val testPayload = byteArrayOf(1, 2, 3, 4)
    val timestamp = 1700000000000L
    val responseFuture =
      messagesService.sendMultiRecipientMessage(
        testPayload,
        timestamp,
        MultiRecipientSendAuthorization.Story,
        onlineOnly = false,
        urgent = true,
      )

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

    assertEquals("PUT", request.method)
    val expectedPath = "/v1/messages/multi_recipient?ts=1700000000000&online=false&urgent=true&story=true"
    assertEquals(expectedPath, request.pathAndQuery)
    assertEquals(mapOf("content-type" to "application/vnd.signal-messenger.mrm"), request.headers)
    assertArrayEquals(testPayload, request.body)

    return Pair(responseFuture, requestId)
  }

  @Test
  fun testSendMultiRecipientMessageSuccess() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestMultiRecipientMessage(chat, fakeRemote)

    // Send successful response with one unregistered UUID
    val uuid = UUID.fromString("4FCFE887-A600-40CD-9AB7-FD2A695E9981")
    val jsonResponse =
      """
      {
        "uuids404": ["$uuid"]
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
    val successResult = assertIs<RequestResult.Success<MultiRecipientMessageResponse>>(result)
    assertEquals(listOf(Aci(uuid)), successResult.result.unregisteredIds)
  }

  @Test
  fun testSendMultiRecipientMessageUnauthorized() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestMultiRecipientMessage(chat, fakeRemote)
    fakeRemote.sendResponse(
      requestId,
      401,
      "Unauthorized",
      arrayOf(),
      byteArrayOf(),
    )

    // Verify the result
    val result = responseFuture.get()
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<MultiRecipientSendFailure>>(result)
    assertIs<RequestUnauthorizedException>(nonSuccessResult.error)
  }

  @Test
  fun testSendMultiRecipientMessageMismatchedDevices() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestMultiRecipientMessage(chat, fakeRemote)

    val uuid = UUID.fromString("4FCFE887-A600-40CD-9AB7-FD2A695E9981")
    val jsonResponse =
      """
      [
        {
          "uuid": "$uuid",
          "devices": {
            "missingDevices": [4, 5],
            "extraDevices": [40, 50]
          }
        }
      ]
      """.trimIndent()

    fakeRemote.sendResponse(
      requestId,
      409,
      "Conflict",
      arrayOf("content-type: application/json"),
      jsonResponse.toByteArray(StandardCharsets.UTF_8),
    )

    // Verify the result
    val result = responseFuture.get()
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<MultiRecipientSendFailure>>(result)
    val mismatchedDevices = assertIs<MismatchedDeviceException>(nonSuccessResult.error)
    assertArrayEquals(
      arrayOf(
        MismatchedDeviceException.Entry(
          Aci(uuid),
          missingDevices = intArrayOf(4, 5),
          extraDevices = intArrayOf(40, 50),
        ),
      ),
      mismatchedDevices.entries,
    )
  }

  @Test
  fun testSendMultiRecipientMessageStaleDevices() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestMultiRecipientMessage(chat, fakeRemote)

    val uuid = UUID.fromString("4FCFE887-A600-40CD-9AB7-FD2A695E9981")
    val jsonResponse =
      """
      [
        {
          "uuid": "$uuid",
          "devices": {
            "staleDevices": [4, 5]
          }
        }
      ]
      """.trimIndent()

    fakeRemote.sendResponse(
      requestId,
      410,
      "Gone",
      arrayOf("content-type: application/json"),
      jsonResponse.toByteArray(StandardCharsets.UTF_8),
    )

    // Verify the result
    val result = responseFuture.get()
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<MultiRecipientSendFailure>>(result)
    val mismatchedDevices = assertIs<MismatchedDeviceException>(nonSuccessResult.error)
    assertArrayEquals(
      arrayOf(
        MismatchedDeviceException.Entry(
          Aci(uuid),
          staleDevices = intArrayOf(4, 5),
        ),
      ),
      mismatchedDevices.entries,
    )
  }

  @Test
  fun testSendMultiRecipientMessageServerSideError() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestMultiRecipientMessage(chat, fakeRemote)
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

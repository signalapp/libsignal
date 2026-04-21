//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.serialization.json.Json
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.protocol.ServiceId.Aci
import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.Future
import kotlin.io.encoding.Base64
import kotlin.test.assertIs

class UnauthMessagesServiceTest {
  private val recipientUuid = UUID.fromString("4FCFE887-A600-40CD-9AB7-FD2A695E9981")

  // From `SERIALIZED_GROUP_SEND_TOKEN` in Rust.
  private val testGroupSendToken =
    GroupSendFullToken(
      Base64.decode("ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo5c+LAQAA"),
    )

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
    val jsonResponse =
      """
      {
        "uuids404": ["$recipientUuid"]
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
    assertEquals(listOf(Aci(recipientUuid)), successResult.result.unregisteredIds)
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

    val jsonResponse =
      """
      [
        {
          "uuid": "$recipientUuid",
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
          Aci(recipientUuid),
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

    val jsonResponse =
      """
      [
        {
          "uuid": "$recipientUuid",
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
          Aci(recipientUuid),
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

  private fun sendTestSealedMessage(
    chat: UnauthenticatedChatConnection,
    auth: UserBasedSendAuthorization,
    expectedAuthHeader: Pair<String, String>?,
    fakeRemote: FakeChatRemote,
  ): Pair<Future<RequestResult<Unit, SealedSendFailure>>, Long> {
    val messagesService = UnauthMessagesService(chat)

    val timestamp = 1700000000000L
    val expectedBody =
      Json.parseToJsonElement(
        """
        {
          "messages": [
            {
              "type": 6,
              "destinationDeviceId": 1,
              "destinationRegistrationId": 11,
              "content": "AQID"
            },
            {
              "type": 6,
              "destinationDeviceId": 2,
              "destinationRegistrationId": 22,
              "content": "BAUG"
            }
          ],
          "online": false,
          "urgent": true,
          "timestamp": 1700000000000
        }
        """,
      )

    val responseFuture =
      messagesService.sendMessage(
        Aci(recipientUuid),
        timestamp,
        listOf(
          SingleOutboundSealedSenderMessage(1, 11, byteArrayOf(1, 2, 3)),
          SingleOutboundSealedSenderMessage(2, 22, byteArrayOf(4, 5, 6)),
        ),
        auth,
        onlineOnly = false,
        urgent = true,
      )

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

    assertEquals("PUT", request.method)
    val expectedPath = "/v1/messages/$recipientUuid" + if (expectedAuthHeader == null) "?story=true" else ""
    assertEquals(expectedPath, request.pathAndQuery)
    assertEquals(listOfNotNull("content-type" to "application/json", expectedAuthHeader).toMap(), request.headers)
    assertEquals(expectedBody, Json.parseToJsonElement(request.body.toString(Charsets.UTF_8)))

    return Pair(responseFuture, requestId)
  }

  @Test
  fun testSendMessageSuccess() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    listOf(
      UserBasedSendAuthorization.Story to null,
      UserBasedAuthorization.AccessKey(ByteArray(16, { 0x0A })) to
        ("unidentified-access-key" to "CgoKCgoKCgoKCgoKCgoKCg=="),
      UserBasedAuthorization.GroupSend(testGroupSendToken) to
        ("group-send-token" to Base64.encode(testGroupSendToken.serialize())),
      UserBasedAuthorization.UnrestrictedUnauthenticatedAccess to
        ("unidentified-access-key" to "AAAAAAAAAAAAAAAAAAAAAA=="),
    ).forEach { (auth, expectedAuthHeader) ->
      val (responseFuture, requestId) = sendTestSealedMessage(chat, auth, expectedAuthHeader, fakeRemote)

      fakeRemote.sendResponse(
        requestId,
        200,
        "OK",
        arrayOf("content-type: application/json"),
        "{}".toByteArray(),
      )

      // Verify the result
      val result = responseFuture.get()
      assertIs<RequestResult.Success<Unit>>(result)
    }
  }

  @Test
  fun testSendMessageNotFound() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestSealedMessage(chat, UserBasedSendAuthorization.Story, null, fakeRemote)
    fakeRemote.sendResponse(
      requestId,
      404,
      "Not Found",
      arrayOf(),
      byteArrayOf(),
    )

    // Verify the result
    val result = responseFuture.get()
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<SealedSendFailure>>(result)
    assertIs<ServiceIdNotFoundException>(nonSuccessResult.error)
  }

  @Test
  fun testSendMessageUnauthorized() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestSealedMessage(chat, UserBasedSendAuthorization.Story, null, fakeRemote)
    fakeRemote.sendResponse(
      requestId,
      401,
      "Unauthorized",
      arrayOf(),
      byteArrayOf(),
    )

    // Verify the result
    val result = responseFuture.get()
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<SealedSendFailure>>(result)
    assertIs<RequestUnauthorizedException>(nonSuccessResult.error)
  }

  @Test
  fun testSendMessageMismatchedDevices() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestSealedMessage(chat, UserBasedSendAuthorization.Story, null, fakeRemote)

    val jsonResponse =
      """
      {
        "missingDevices": [4, 5],
        "extraDevices": [40, 50]
      }
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
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<SealedSendFailure>>(result)
    val mismatchedDevices = assertIs<MismatchedDeviceException>(nonSuccessResult.error)
    assertArrayEquals(
      arrayOf(
        MismatchedDeviceException.Entry(
          Aci(recipientUuid),
          missingDevices = intArrayOf(4, 5),
          extraDevices = intArrayOf(40, 50),
        ),
      ),
      mismatchedDevices.entries,
    )
  }

  @Test
  fun testSendMessageStaleDevices() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val (responseFuture, requestId) = sendTestSealedMessage(chat, UserBasedSendAuthorization.Story, null, fakeRemote)

    val jsonResponse =
      """
      {
        "staleDevices": [4, 5]
      }
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
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<SealedSendFailure>>(result)
    val mismatchedDevices = assertIs<MismatchedDeviceException>(nonSuccessResult.error)
    assertArrayEquals(
      arrayOf(
        MismatchedDeviceException.Entry(
          Aci(recipientUuid),
          staleDevices = intArrayOf(4, 5),
        ),
      ),
      mismatchedDevices.entries,
    )
  }
}

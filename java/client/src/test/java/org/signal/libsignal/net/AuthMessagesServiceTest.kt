//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.serialization.json.Json
import org.junit.Test
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.protocol.ServiceId.Aci
import org.signal.libsignal.protocol.message.PlaintextContent
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthMessagesServiceTest {
  private val recipientUuid = UUID.fromString("4FCFE887-A600-40CD-9AB7-FD2A695E9981")

  @Test
  fun testGetUploadForm() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      AuthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
      )

    val service = AuthMessagesService(chat)
    val responseFuture = service.getUploadForm(42)
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get(1, TimeUnit.SECONDS)
    assertEquals("GET", request.method)
    assertEquals("/v4/attachments/form/upload?uploadLength=42", request.pathAndQuery)
    assertEquals(0, request.headers.size)
    assertEquals(0, request.body.size)
    fakeRemote.sendResponse(
      requestId,
      200,
      "OK",
      arrayOf("content-type: application/json"),
      """
        {
          "cdn":123,
          "key":"abcde",
          "headers":{"one":"val1","two":"val2"},
          "signedUploadLocation":"http://example.org/upload"
        }
      """.encodeToByteArray(),
    )
    val result = responseFuture.get()
    val successResult = assertIs<RequestResult.Success<UploadForm>>(result)
    assertEquals(
      UploadForm(
        cdn = 123,
        key = "abcde",
        headers = mapOf("one" to "val1", "two" to "val2"),
        signedUploadUrl = URI("http://example.org/upload"),
      ),
      successResult.result,
    )
  }

  @Test
  fun testGetUploadFormTooLarge() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      AuthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
      )

    val service = AuthMessagesService(chat)
    val responseFuture = service.getUploadForm(42)
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get(1, TimeUnit.SECONDS)
    assertEquals("GET", request.method)
    assertEquals("/v4/attachments/form/upload?uploadLength=42", request.pathAndQuery)
    assertEquals(0, request.headers.size)
    assertEquals(0, request.body.size)
    fakeRemote.sendResponse(
      requestId,
      413,
      "Content Too Large",
      arrayOf(),
      byteArrayOf(),
    )
    val error = assertIs<RequestResult.NonSuccess<UploadTooLargeException>>(responseFuture.get()).error
    assertIs<UploadTooLargeException>(error)
  }

  private fun sendTestMessage(
    chat: AuthenticatedChatConnection,
    syncMessage: Boolean,
    fakeRemote: FakeChatRemote,
  ): Pair<Future<out RequestResult<Unit, BadRequestError>>, Long> {
    val messagesService = AuthMessagesService(chat)

    val timestamp = 1700000000000L
    val expectedBody =
      Json.parseToJsonElement(
        """
        {
          "messages": [
            {
              "type": 8,
              "destinationDeviceId": 1,
              "destinationRegistrationId": 11,
              "content": "wAECA4A="
            },
            {
              "type": 8,
              "destinationDeviceId": 2,
              "destinationRegistrationId": 22,
              "content": "wAQFBoA="
            }
          ],
          "online": false,
          "urgent": true,
          "timestamp": 1700000000000
        }
        """,
      )

    val messages =
      listOf(
        SingleOutboundUnsealedMessage(1, 11, PlaintextContent(byteArrayOf(0xC0.toByte(), 1, 2, 3, 0x80.toByte()))),
        SingleOutboundUnsealedMessage(2, 22, PlaintextContent(byteArrayOf(0xC0.toByte(), 4, 5, 6, 0x80.toByte()))),
      )
    val responseFuture =
      if (syncMessage) {
        messagesService.sendSyncMessage(
          timestamp,
          messages,
          urgent = true,
        )
      } else {
        messagesService.sendMessage(
          Aci(recipientUuid),
          timestamp,
          messages,
          onlineOnly = false,
          urgent = true,
        )
      }

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingRequest().get()

    assertEquals("PUT", request.method)
    val expectedUuid = if (syncMessage) FakeChatRemote.FAKE_AUTH_CONNECT_SELF_UUID else recipientUuid
    assertEquals("/v1/messages/$expectedUuid", request.pathAndQuery)
    assertEquals(
      mapOf("content-type" to "application/json"),
      request.headers,
    )
    assertEquals(expectedBody, Json.parseToJsonElement(request.body.toString(Charsets.UTF_8)))

    return Pair(responseFuture, requestId)
  }

  @Test
  fun testSendMessageSuccess() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      AuthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        emptyArray(),
      )

    listOf(
      false,
      true,
    ).forEach { syncMessage ->
      val (responseFuture, requestId) = sendTestMessage(chat, syncMessage, fakeRemote)

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
      AuthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        emptyArray(),
      )

    val (responseFuture, requestId) = sendTestMessage(chat, syncMessage = false, fakeRemote)
    fakeRemote.sendResponse(
      requestId,
      404,
      "Not Found",
      arrayOf(),
      byteArrayOf(),
    )

    // Verify the result
    val result = responseFuture.get()
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<UnsealedSendFailure>>(result)
    assertIs<ServiceIdNotFoundException>(nonSuccessResult.error)
  }

  @Test
  fun testSendMessageMismatchedDevices() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      AuthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        emptyArray(),
      )

    val (responseFuture, requestId) = sendTestMessage(chat, syncMessage = false, fakeRemote)

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
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<UnsealedSendFailure>>(result)
    val mismatchedDevices = assertIs<MismatchedDeviceException>(nonSuccessResult.error)
    assertContentEquals(
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
      AuthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        emptyArray(),
      )

    val (responseFuture, requestId) = sendTestMessage(chat, syncMessage = false, fakeRemote)

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
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<UnsealedSendFailure>>(result)
    val mismatchedDevices = assertIs<MismatchedDeviceException>(nonSuccessResult.error)
    assertContentEquals(
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
  fun testSendMessageCaptcha() {
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      AuthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        emptyArray(),
      )

    val (responseFuture, requestId) = sendTestMessage(chat, syncMessage = false, fakeRemote)

    val jsonResponse =
      """
      {
        "token": "zzz",
        "options": ["captcha"]
      }
      """.trimIndent()

    fakeRemote.sendResponse(
      requestId,
      428,
      "Precondition Required",
      arrayOf("content-type: application/json"),
      jsonResponse.toByteArray(StandardCharsets.UTF_8),
    )

    // Verify the result
    val result = responseFuture.get()
    val nonSuccessResult = assertIs<RequestResult.NonSuccess<UnsealedSendFailure>>(result)
    val challengeException = assertIs<RateLimitChallengeException>(nonSuccessResult.error)
    assertEquals("zzz", challengeException.token)
    assertEquals(setOf(ChallengeOption.CAPTCHA), challengeException.options)
  }
}

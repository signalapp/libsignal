//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.junit.Test
import org.signal.libsignal.internal.TokioAsyncContext
import java.net.URI
import java.util.concurrent.TimeUnit
import kotlin.arrayOf
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthMessagesServiceTest {
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
}

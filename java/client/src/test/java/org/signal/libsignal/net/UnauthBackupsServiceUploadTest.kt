/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal.net

import org.junit.Test
import org.signal.libsignal.internal.NativeTesting
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.zkgroup.GenericServerPublicParams
import org.signal.libsignal.zkgroup.backups.BackupAuthCredential
import java.net.URI
import kotlin.io.encoding.Base64
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals

class UnauthBackupsServiceUploadTest {
  companion object {
    // These constants are from api/backups.rs
    val TEST_CREDENTIAL =
      Base64.decode(
        "AACkl2kAAAAAyQAAAAAAAAACAAAAAAAAAMUH8mZNP0qDpXFbK2e3dKL04Zw1UhyJ5ab+RlRLhAYELu5/fvwOhxzvxcnNGpqppkGOWc7SSN0kEU0MMIslejR+FDPRx0BWeRTeMmr2ngFVaHUjmazUmgCAPkr0BuLjShTidN9UW8r2M6FjodEtF/8=",
      )
    val TEST_SERVER_KEYS =
      Base64.decode(
        "AIRCHmMrkZXZ9ZuwKJkA0GeMOaDSdVsU26AghADhY3l5XBYwf0UCtm2tvvYsbnPgh9uIUyERm0Wg3v7pFtg+OEfsM6fwjdBFqAgfeqs1pT9nwp2Wp6oGdAfCTrGcqraXJoyAiwAh3vogu7ltucNKh25zKiOkIeIEJNrjbx2eEwkFnqLYuk/noxaOi2Zl7R5d7+vn0Me0d2AZhu0Uuk1vpTIuYf+X4UJXV/N5TYYxwOe/OQHu4zZmdaPjtPN1EHFJC5ALV+8BY9dN5ddS7iTL1uq1ksURAA9hAZzC9/aTr7J7",
      )
    val TEST_SIGNING_KEY =
      Base64.decode(
        "KMhdmPEusAwoT3C2LzIbmGX6z+3HMbhgbrXmUwRfGF0=",
      )
    val EXPECTED_PRESENTATION =
      Base64.decode(
        "AMkAAAAAAAAAAgAAAAAAAAAApJdpAAAAAIoiVNK2DtZIRFCtQxRiSokkSiQEKrUm86QgMg+qyZZjLuJipcWuggZt6au2i4MOhslTP4qafDZUYWZnKdX7zV4MKW1+FqHVi9kns3+gGaHRCrUEqKcTBzZj/C79ZRJObwIAAAAAAAAA7vpvGr5uokinX1GRCgDr5au1ajuE2naAsAUXPXXpxTyKZo+S3m3OdyDUusIM3sIyUFwM1OeMtmHLgDcuGAqKdYAAAAAAAAAAcqkJSxGNgTB4ERB7Qcg8tp+IZnEhGxCzuvY3KqrjgwA1LniEMcZCO9kjcSL2Q5JS5yZYrv7Kkn0p3hY4vIrKBlgb0zycYLKRrUj+ndkHKJtWV/2xC42jehDUc1P2ufIEJfu4ScD+sUt9fgAV7uDsKI/ktXnhUPT7/ZxtCCp88gEU4nTfVFvK9jOhY6HRLRf/",
      )
    val EXPECTED_SIGNATURE =
      Base64.decode(
        "TUmhLTMN7LLUOphZiAF8WZekmWzYDWlDiqNm3LirWwcSotw+yUd+MOizCpwVD+Wp9dLHjqU00xUwm+KnxtiKiA==",
      )
    val TEST_AUTH =
      BackupAuth(
        BackupAuthCredential(TEST_CREDENTIAL),
        GenericServerPublicParams(TEST_SERVER_KEYS),
        ECPrivateKey(TEST_SIGNING_KEY),
      )

    val functions =
      listOf(
        "/v1/archives/upload/form" to UnauthBackupsService::getUploadForm,
        "/v1/archives/media/upload/form" to UnauthBackupsService::getMediaUploadForm,
      )
  }

  @Test
  fun returnsDifferentValuesIfRngNotProvided() {
    for ((_, func) in functions) {
      val tokioAsyncContext = TokioAsyncContext()
      val (chat, fakeRemote) =
        UnauthenticatedChatConnection.fakeConnect(
          tokioAsyncContext,
          NoOpListener(),
          Network.Environment.STAGING,
        )
      val service = UnauthBackupsService(chat)
      func(
        service,
        TEST_AUTH,
        12345,
        null,
      )
      val (request1, request1Id) = fakeRemote.getNextIncomingRequest().get()
      fakeRemote.sendResponse(request1Id, 500, "Internal Server Error", arrayOf(), byteArrayOf())
      func(
        service,
        TEST_AUTH,
        12345,
        null,
      )
      val (request2, request2Id) = fakeRemote.getNextIncomingRequest().get()
      fakeRemote.sendResponse(request2Id, 500, "Internal Server Error", arrayOf(), byteArrayOf())
      assertNotEquals(request1.headers["x-signal-zk-auth"], request2.headers["x-signal-zk-auth"])
    }
  }

  @Test
  fun testSuccess() {
    NativeTesting.TESTING_EnableDeterministicRngForTesting()
    for ((endpoint, func) in functions) {
      val tokioAsyncContext = TokioAsyncContext()
      val (chat, fakeRemote) =
        UnauthenticatedChatConnection.fakeConnect(
          tokioAsyncContext,
          NoOpListener(),
          Network.Environment.STAGING,
        )
      val service = UnauthBackupsService(chat)
      val responseFuture =
        func(
          service,
          TEST_AUTH,
          12345,
          DeterministicRandomSeedUseOnlyForTesting(0),
        )
      val (request, requestId) = fakeRemote.getNextIncomingRequest().get()
      assertEquals(request.method, "GET")
      assertEquals(request.pathAndQuery, "$endpoint?uploadLength=12345")
      assertEquals(
        request.headers,
        mapOf(
          "x-signal-zk-auth" to Base64.encode(EXPECTED_PRESENTATION),
          "x-signal-zk-auth-signature" to Base64.encode(EXPECTED_SIGNATURE),
        ),
      )
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
  }

  @Test
  fun testUploadTooLarge() {
    for ((endpoint, func) in functions) {
      val tokioAsyncContext = TokioAsyncContext()
      val (chat, fakeRemote) =
        UnauthenticatedChatConnection.fakeConnect(
          tokioAsyncContext,
          NoOpListener(),
          Network.Environment.STAGING,
        )
      val service = UnauthBackupsService(chat)

      fun testError(
        cls: Class<*>,
        code: Int,
      ) {
        val responseFuture =
          func(
            service,
            TEST_AUTH,
            12345,
            null,
          )
        val (request, requestId) = fakeRemote.getNextIncomingRequest().get()
        fakeRemote.sendResponse(
          requestId,
          code,
          "Upload Too Large",
          arrayOf(),
          byteArrayOf(),
        )
        val result = responseFuture.get()
        val errorResult = assertIs<RequestResult.NonSuccess<GetUploadFormError>>(result)
        assertEquals<Any>(errorResult.error.javaClass, cls)
      }
      testError(UploadTooLargeException::class.java, 413)
      testError(RequestUnauthorizedException::class.java, 403)
    }
  }
}

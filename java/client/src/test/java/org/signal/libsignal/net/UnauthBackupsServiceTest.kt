/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.libsignal.net

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.junit.Assert
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.signal.libsignal.internal.CompletableFuture
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
val TEST_SIGNING_KEY_PUB = Base64.decode("BWp7eOx6q6IlijMPozln1bY34JoLFZhGu3PLDnn7hO9t")
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

class UnauthBackupsServiceUploadTest {
  companion object {
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

class UnauthBackupsServiceTest {
  fun buildBackupRequestObject(builderAction: JsonObjectBuilder.() -> Unit = {}): JsonObject =
    buildJsonObject {
      putJsonObject("signedPresentation") {
        put("presentation", Base64.encode(EXPECTED_PRESENTATION))
        put("presentationSignature", Base64.encode(EXPECTED_SIGNATURE))
      }
      builderAction()
    }

  // TODO: Move this to a more reusable location.
  fun <T, E : BadRequestError> testSimpleGrpcRequest(
    requestName: String,
    expectedRequest: JsonObject,
    responseName: String,
    response: JsonObject,
    sendRequest: UnauthenticatedChatConnection.() -> CompletableFuture<RequestResult<T, E>>,
  ): RequestResult<T, E> {
    NativeTesting.TESTING_EnableDeterministicRngForTesting()
    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val responseFuture = chat.sendRequest()

    // Get the incoming request from the fake remote
    val (request, requestId) = fakeRemote.getNextIncomingGrpcRequest().get()
    Assert.assertEquals(
      request.getSingleGrpcMessage(requestName),
      expectedRequest,
    )

    // Send successful response
    fakeRemote.sendGrpcResponse(
      requestId,
      responseName,
      response,
    )

    return responseFuture.get()
  }

  fun <T, E : BadRequestError> testSimpleBackupRequestSuccess(
    requestName: String,
    expectedRequest: JsonObject,
    responseName: String,
    response: JsonObject,
    sendRequest: UnauthBackupsService.() -> CompletableFuture<RequestResult<T, E>>,
  ): T {
    val result =
      testSimpleGrpcRequest(requestName, expectedRequest, responseName, response) {
        UnauthBackupsService(this).sendRequest()
      }
    val successResult = assertIs<RequestResult.Success<T>>(result)
    assertNotNull(successResult.result)
    return successResult.result
  }

  fun <T, E : BadRequestError> testSimpleBackupRequestUnauthorized(
    requestName: String,
    expectedRequest: JsonObject,
    responseName: String,
    sendRequest: UnauthBackupsService.() -> CompletableFuture<RequestResult<T, E>>,
  ) {
    val result =
      testSimpleGrpcRequest(
        requestName,
        expectedRequest,
        responseName,
        buildJsonObject {
          // There's no rule that says all the failed authentication responses HAVE to have the same oneof field name.
          // But in practice they do.
          putJsonObject("failedAuthentication") {
            put("description", "bad auth")
          }
        },
      ) {
        UnauthBackupsService(this).sendRequest()
      }
    val nonSuccess = assertIs<RequestResult.NonSuccess<E>>(result)
    assertIs<RequestUnauthorizedException>(nonSuccess.error)
  }

  @Test
  fun testSetPublicKey() {
    testSimpleBackupRequestSuccess(
      "org.signal.chat.backup.SetPublicKeyRequest",
      buildBackupRequestObject {
        put("publicKey", Base64.encode(TEST_SIGNING_KEY_PUB))
      },
      "org.signal.chat.backup.SetPublicKeyResponse",
      buildJsonObject {
        putJsonObject("success") {}
      },
    ) {
      @Suppress("DEPRECATION")
      setPublicKey(
        TEST_AUTH,
        DeterministicRandomSeedUseOnlyForTesting(0),
      )
    }

    testSimpleBackupRequestUnauthorized(
      "org.signal.chat.backup.SetPublicKeyRequest",
      buildBackupRequestObject {
        put("publicKey", Base64.encode(TEST_SIGNING_KEY_PUB))
      },
      "org.signal.chat.backup.SetPublicKeyResponse",
    ) {
      @Suppress("DEPRECATION")
      setPublicKey(
        TEST_AUTH,
        DeterministicRandomSeedUseOnlyForTesting(0),
      )
    }
  }

  @Test
  fun testRefresh() {
    testSimpleBackupRequestSuccess(
      "org.signal.chat.backup.RefreshRequest",
      buildBackupRequestObject(),
      "org.signal.chat.backup.RefreshResponse",
      buildJsonObject {
        putJsonObject("success") {}
      },
    ) {
      @Suppress("DEPRECATION")
      refresh(
        TEST_AUTH,
        DeterministicRandomSeedUseOnlyForTesting(0),
      )
    }

    testSimpleBackupRequestUnauthorized(
      "org.signal.chat.backup.RefreshRequest",
      buildBackupRequestObject(),
      "org.signal.chat.backup.RefreshResponse",
    ) {
      @Suppress("DEPRECATION")
      refresh(
        TEST_AUTH,
        DeterministicRandomSeedUseOnlyForTesting(0),
      )
    }
  }

  @Test
  fun testDeleteAll() {
    testSimpleBackupRequestSuccess(
      "org.signal.chat.backup.DeleteAllRequest",
      buildBackupRequestObject(),
      "org.signal.chat.backup.DeleteAllResponse",
      buildJsonObject {
        putJsonObject("success") {}
      },
    ) {
      @Suppress("DEPRECATION")
      deleteAll(
        TEST_AUTH,
        DeterministicRandomSeedUseOnlyForTesting(0),
      )
    }
    testSimpleBackupRequestUnauthorized(
      "org.signal.chat.backup.DeleteAllRequest",
      buildBackupRequestObject(),
      "org.signal.chat.backup.DeleteAllResponse",
    ) {
      @Suppress("DEPRECATION")
      deleteAll(
        TEST_AUTH,
        DeterministicRandomSeedUseOnlyForTesting(0),
      )
    }
  }

  @Test
  fun testGetCdnCredentials() {
    val credentials =
      testSimpleBackupRequestSuccess(
        "org.signal.chat.backup.GetCdnCredentialsRequest",
        buildBackupRequestObject {
          put("cdn", 40)
        },
        "org.signal.chat.backup.GetCdnCredentialsResponse",
        buildJsonObject {
          putJsonObject("cdnCredentials") {
            putJsonObject("headers") {
              put("b", "bbb")
              put("a", "aaa")
            }
          }
        },
      ) {
        @Suppress("DEPRECATION")
        getCdnCredentials(
          TEST_AUTH,
          40,
          DeterministicRandomSeedUseOnlyForTesting(0),
        )
      }
    Assert.assertEquals(credentials, BackupCdnCredentials(mapOf("a" to "aaa", "b" to "bbb")))

    testSimpleBackupRequestUnauthorized(
      "org.signal.chat.backup.GetCdnCredentialsRequest",
      buildBackupRequestObject {
        put("cdn", 40)
      },
      "org.signal.chat.backup.GetCdnCredentialsResponse",
    ) {
      @Suppress("DEPRECATION")
      getCdnCredentials(
        TEST_AUTH,
        40,
        DeterministicRandomSeedUseOnlyForTesting(0),
      )
    }
  }

  @Test
  fun testGetSvrBCredentials() {
    val credentials =
      testSimpleBackupRequestSuccess(
        "org.signal.chat.backup.GetSvrBCredentialsRequest",
        buildBackupRequestObject(),
        "org.signal.chat.backup.GetSvrBCredentialsResponse",
        buildJsonObject {
          putJsonObject("svrbCredentials") {
            put("username", "user")
            put("password", "pass")
          }
        },
      ) {
        @Suppress("DEPRECATION")
        getSvrBCredentials(
          TEST_AUTH,
          DeterministicRandomSeedUseOnlyForTesting(0),
        )
      }
    Assert.assertEquals(credentials, "user" to "pass")

    testSimpleBackupRequestUnauthorized(
      "org.signal.chat.backup.GetSvrBCredentialsRequest",
      buildBackupRequestObject(),
      "org.signal.chat.backup.GetSvrBCredentialsResponse",
    ) {
      @Suppress("DEPRECATION")
      getSvrBCredentials(
        TEST_AUTH,
        DeterministicRandomSeedUseOnlyForTesting(0),
      )
    }
  }
}

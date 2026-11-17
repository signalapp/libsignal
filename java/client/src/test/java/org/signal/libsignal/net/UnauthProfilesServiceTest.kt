//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.signal.libsignal.internal.ExtendAvatarTtlOut
import org.signal.libsignal.internal.GetAvatarUploadFormOut
import org.signal.libsignal.internal.GetProfileKeyCredentialOut
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.ProfileKeyCredentialRequestError
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.internal.UnauthGetProfileError
import org.signal.libsignal.internal.UnauthGetProfileOut
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredential
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.arrayOf
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs
import org.signal.libsignal.internal.UnauthProfileAuthorization as UnauthProfileAuthorizationInternal

class UnauthProfilesServiceTest {
  @Test
  fun testAccountExists() {
    data class TestCase(
      val serviceId: ServiceId,
      val found: Boolean,
    )

    val aci = ServiceId.Aci(UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"))
    val pni = ServiceId.Pni(UUID.fromString("796abedb-ca4e-4f18-8803-1fde5b921f9f"))

    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        arrayOf("AccountsAnonymousCheckAccountExistence"),
        Network.Environment.STAGING,
      )

    val profilesService = UnauthProfilesService(chat)

    for (testCase in listOf(
      TestCase(aci, true),
      TestCase(pni, true),
      TestCase(aci, false),
      TestCase(pni, false),
    )) {
      val responseFuture = profilesService.accountExists(testCase.serviceId)
      val (request, requestId) = fakeRemote.getNextIncomingRequest().get(1, TimeUnit.SECONDS)
      assertEquals("HEAD", request.method)
      assertEquals("/v1/accounts/account/${testCase.serviceId.toServiceIdString()}", request.pathAndQuery)
      fakeRemote.sendResponse(
        requestId,
        if (testCase.found) 200 else 404,
        if (testCase.found) "OK" else "Not Found",
        arrayOf(),
        ByteArray(0),
      )
      val result = responseFuture.get()
      val successResult = assertIs<RequestResult.Success<Boolean>>(result)
      assertEquals(testCase.found, successResult.result)
    }
  }

  @Test
  fun testGetProfileKeyCredential() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetProfileKeyCredentialTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthProfilesService,
        invoke = { chat, req ->
          chat.getProfileKeyCredential(
            requestContext = req.profileKeyRequestContext,
            serverParams = ServerPublicParams(req.serverParams.bytes),
          )
        },
        check = { expected, actual ->
          when (expected) {
            is GetProfileKeyCredentialOut.Success ->
              assertEquals(
                expected._0,
                assertIs<RequestResult.Success<ExpiringProfileKeyCredential>>(actual).result,
              )
            is GetProfileKeyCredentialOut.ExplicitError ->
              when (expected._0) {
                ProfileKeyCredentialRequestError.AuthFailed ->
                  actual.assertNonSuccess<_, _, RequestUnauthorizedException>()
                ProfileKeyCredentialRequestError.ProfileNotFound ->
                  actual.assertNonSuccess<_, _, ProfileNotFoundException>()
              }
            is GetProfileKeyCredentialOut.UnexpectedError ->
              assertContains(assertIs<RequestResult.ApplicationError>(actual).toString(), expected.contains)
          }
        },
      )
    }

  @Test
  fun testExtendAvatarTtl() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_ExtendAvatarTtlTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthProfilesService,
        invoke = { chat, req ->
          chat.extendAvatarTtl(
            credential = req,
          )
        },
        check = { expected, actual ->
          when (expected) {
            is ExtendAvatarTtlOut.Found -> assertEquals(actual.assertSuccess(), expected._0)
            ExtendAvatarTtlOut.InvalidCredentials ->
              actual
                .assertNonSuccess<_, _, InvalidAvatarUploadCredentialPresentationException>()
            ExtendAvatarTtlOut.NotFound -> assertEquals(null, actual.assertSuccess())
          }
        },
      )
    }
  }

  @Test
  fun testDeleteAvatar() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_DeleteAvatarTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthProfilesService,
        invoke = { chat, req ->
          chat.deleteAvatar(
            credential = req,
          )
        },
        check = { expected, actual ->
          if (expected) {
            actual.assertSuccess()
          } else {
            actual.assertNonSuccess<_, _, InvalidAvatarUploadCredentialPresentationException>()
          }
        },
      )
    }
  }

  @Test
  fun testGetAvatarUploadForm() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetAvatarUploadFormTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthProfilesService,
        invoke = { chat, req ->
          chat.getAvatarUploadForm(
            credential = req.credential,
            uploadLength = req.uploadLength,
          )
        },
        check = { expected, actual ->
          when (expected) {
            GetAvatarUploadFormOut.InvalidCredential ->
              actual
                .assertNonSuccess<_, _, InvalidAvatarUploadCredentialPresentationException>()
            is GetAvatarUploadFormOut.Success -> assertEquals(expected._0, actual.assertSuccess())
          }
        },
      )
    }
  }

  @Test
  fun testGetProfile() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_UnauthGetProfileTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthProfilesService,
        invoke = { chat, req ->
          chat.getProfile(
            aci = req.inner.aci,
            profileKey = req.inner.profileKey,
            auth =
              when (req.auth) {
                is UnauthProfileAuthorizationInternal.GroupSend ->
                  UnauthProfileAuthorization
                    .GroupSend(
                      req.auth._0,
                    )
                is UnauthProfileAuthorizationInternal.AccessKey ->
                  UnauthProfileAuthorization
                    .AccessKey(
                      req.auth._0,
                    )
              },
            etag = req.inner.etag,
          )
        },
        check = { expected, actual ->
          when (expected) {
            is UnauthGetProfileOut.Failure ->
              when (expected._0) {
                is UnauthGetProfileError.ProfileDecodeError ->
                  actual.assertNonSuccess<_, _, ProfileCantBeDecodedException>()
                UnauthGetProfileError.ProfileNotFound ->
                  actual.assertNonSuccess<_, _, ProfileNotFoundException>()
                UnauthGetProfileError.FailedUnidentifiedAuthorization ->
                  actual
                    .assertNonSuccess<_, _, RequestUnauthorizedException>()
              }
            is UnauthGetProfileOut.Success ->
              assertEquals(expected._0, actual.assertSuccess())
          }
        },
      )
    }
  }
}

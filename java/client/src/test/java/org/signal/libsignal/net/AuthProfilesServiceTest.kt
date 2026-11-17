//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.signal.libsignal.internal.AuthGetProfileError
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.GetProfileOut
import org.signal.libsignal.internal.NativeTesting
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.SetProfileArgs
import org.signal.libsignal.internal.SetProfileError
import org.signal.libsignal.internal.SetProfileOut
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.internal.await
import org.signal.libsignal.net.assertNonSuccess
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

class AuthProfilesServiceTest {
  @Test
  fun testGetAvatarUploadFormLegacy() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetAvatarUploadFormLegacyTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthProfilesService,
        invoke = { chat, req ->
          chat.getAvatarUploadFormLegacy(
            aci = req.aci,
            profileKey = req.profileKey,
          )
        },
        check = { expected, actual ->
          assertEquals(expected, actual.assertSuccess())
        },
      )
    }
  }

  @Test
  fun testGetAvatarCredential() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetAvatarCredentialTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthProfilesService,
        invoke = { chat, req ->
          chat.getAvatarCredential(
            aci = req.aci,
            keyPair = req.keyPair,
            rotationId = req.rotationId,
            serverPublicParams = req.serverPublicParams,
            currentTimeSeconds = Instant.ofEpochSecond(req.currentTimeSeconds),
            rng = DeterministicRandomSeedUseOnlyForTesting(0),
          )
        },
        check = { expected, actual ->
          if (expected == null) {
            actual.assertNonSuccess<_, _, AccountMissingZkCredentialKeyException>()
          } else {
            assertEquals(expected, actual.assertSuccess())
          }
        },
      )
    }
  }

  private object SetProfileHelpers {
    fun invoke(
      chat: AuthProfilesService,
      req: SetProfileArgs,
    ): CompletableFuture<RequestResult<ProfileDataHash, SetProfileException>> =
      chat.setProfile(
        rng = DeterministicRandomSeedUseOnlyForTesting(req.rngSeed),
        aci = req.aci,
        profileKey = req.profileKey,
        profile = req.profile,
        expectedCurrentDataHash = req.expectedCurrentDataHash,
        expectedCurrentProfileKeyVersion = req.expectedCurrentProfileKeyVersion,
      )

    fun check(
      expected: SetProfileOut,
      actual: RequestResult<ProfileDataHash, SetProfileException>,
    ) {
      when (expected) {
        is SetProfileOut.Failure -> {
          val err = expected._0
          when (err) {
            SetProfileError.ExpectedDataWriteConflict ->
              actual
                .assertNonSuccess<_, _, SetProfileException.ExpectedDataWriteConflict>()

            is SetProfileError.ExpectedVersionWriteConflict ->
              assertEquals(
                actual
                  .assertNonSuccess<_, _, SetProfileException.ExpectedVersionWriteConflict>()
                  .currentProfileVersion,
                err.currentProfileVersion,
              )

            is SetProfileError.InvalidProfile ->
              assertEquals(
                actual.assertNonSuccess<_, _, SetProfileException.InvalidProfile>().profileValidationError,
                err._0,
              )

            SetProfileError.PaymentsForbiddenInRegion ->
              actual
                .assertNonSuccess<_, _, SetProfileException.PaymentsForbiddenInRegion>()
          }
        }

        is SetProfileOut.Success -> assertContentEquals(actual.assertSuccess(), expected._0)
      }
    }
  }

  @Test
  fun testSetProfile() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetProfileTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthProfilesService,
        invoke = SetProfileHelpers::invoke,
        check = SetProfileHelpers::check,
      )
    }
  }

  @Test
  fun testSetProfileValidation() {
    NativeTesting.TESTING_EnableDeterministicRngForTesting()
    runTest {
      for (test in NativeTestingNice.TESTING_SetProfileValidationTests()) {
        println("Running test ${test.name}")
        coroutineScope {
          val tokioAsyncContext = TokioAsyncContext()
          val (chat, _) = AuthenticatedChatConnection.fakeConnect(tokioAsyncContext, NoOpListener())
          val actual =
            withContext(Dispatchers.Default.limitedParallelism(1)) {
              withTimeout(5.seconds) {
                SetProfileHelpers.invoke(AuthProfilesService(chat), test.request).await()
              }
            }
          SetProfileHelpers.check(test.response, actual)
        }
      }
    }
  }

  @Test
  fun testProfileFieldMaxLength() {
    for ((field, maxLength) in NativeTestingNice.TESTING_ProfileFieldMaxLengths()) {
      assertEquals(field.maxLength, maxLength)
    }
  }

  @Test
  fun testGetProfile() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetProfileTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthProfilesService,
        invoke = { chat, req ->
          chat.getProfile(
            aci = req.aci,
            profileKey = req.profileKey,
            etag = req.etag,
          )
        },
        check = { expected, actual ->
          when (expected) {
            is GetProfileOut.Failure ->
              when (expected._0) {
                is AuthGetProfileError.ProfileDecodeError ->
                  actual.assertNonSuccess<_, _, ProfileCantBeDecodedException>()
                AuthGetProfileError.ProfileNotFound ->
                  actual.assertNonSuccess<_, _, ProfileNotFoundException>()
              }
            is GetProfileOut.Success ->
              assertEquals(expected._0, actual.assertSuccess())
          }
        },
      )
    }
  }
}

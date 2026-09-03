//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.BridgeConfirmedMfaKeyMetadata
import org.signal.libsignal.internal.BridgeMfaKeyKind
import org.signal.libsignal.internal.ConfirmTotpKeyOut
import org.signal.libsignal.internal.GenerateTotpKeyOut
import org.signal.libsignal.internal.ListMfaKeysOut
import org.signal.libsignal.internal.NativeTesting
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.RemoveMfaKeyOut
import org.signal.libsignal.internal.SetMfaKeyMetadataOut
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.internal.await
import org.signal.libsignal.net.assertNonSuccess
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class AuthAccountsServiceTest {
  @Test
  fun testDeleteAccount() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_DeleteAccountTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, _ ->
          chat.deleteAccount()
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testSetRegistrationLock() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetRegistrationLockTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, req ->
          chat.setRegistrationLock(svrKey = SvrKey(req))
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testClearRegistrationLock() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_ClearRegistrationLockTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, _ ->
          chat.clearRegistrationLock()
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testSetRegistrationRecoveryPassword() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetRegistrationRecoveryPasswordTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, req ->
          chat.setRegistrationRecoveryPassword(svrKey = SvrKey(req))
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testSetDiscoverableByPhoneNumber() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetDiscoverableByPhoneNumberTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, req ->
          chat.setDiscoverableByPhoneNumber(discoverable = req)
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testGenerateTotpKey() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GenerateTotpKeyTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, _ ->
          chat.generateTotpKey()
        },
        check = { expected, actual ->
          when (expected) {
            is GenerateTotpKeyOut.Success ->
              assertEquals(
                PendingTotpKey.fromInternal(expected._0),
                assertIs<RequestResult.Success<PendingTotpKey>>(actual).result,
              )
            GenerateTotpKeyOut.TooManyTotpKeys ->
              actual.assertNonSuccess<_, _, TooManyTotpKeysException>()
            GenerateTotpKeyOut.TooManyMfaKeys ->
              actual.assertNonSuccess<_, _, TooManyMfaKeysException>()
          }
        },
      )
    }

  @Test
  fun testConfirmTotpKey() =
    runTest {
      NativeTesting.TESTING_EnableDeterministicRngForTesting()
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_ConfirmTotpKeyTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, req ->
          chat.confirmTotpKey(
            oneTimePassword = req.oneTimePassword,
            metadata = MfaMetadata(name = req.name, createdAt = req.createdAt),
            svrKey = SvrKey(req.svrKey),
            rngSeedForTesting = DeterministicRandomSeedUseOnlyForTesting(0),
          )
        },
        check = { expected, actual ->
          when (expected) {
            is ConfirmTotpKeyOut.Success ->
              assertEquals(
                expected._0,
                assertIs<RequestResult.Success<Int>>(actual).result,
              )
            ConfirmTotpKeyOut.OneTimePasswordNotVerified ->
              actual.assertNonSuccess<_, _, OneTimePasswordNotVerifiedException>()
            ConfirmTotpKeyOut.TooManyMfaKeys ->
              actual.assertNonSuccess<_, _, TooManyMfaKeysException>()
          }
        },
      )
    }

  @Test
  fun testTotpKeyNameInvalid() =
    runTest {
      val tokioAsyncContext = TokioAsyncContext()
      val (chat, _) = AuthenticatedChatConnection.fakeConnect(tokioAsyncContext, NoOpListener())
      val service = AuthAccountsService(chat)

      for (invalidName in listOf("a".repeat(MfaMetadata.NAME_MAX_LENGTH + 1), "before\u0000after")) {
        val metadata = MfaMetadata(name = invalidName, createdAt = Instant.EPOCH)
        val confirmResult =
          service
            .confirmTotpKey(
              oneTimePassword = 123456,
              metadata = metadata,
              svrKey = SvrKey(ByteArray(32)),
            ).await()
        assertIs<IllegalArgumentException>(assertIs<RequestResult.ApplicationError>(confirmResult).cause)

        val setResult =
          service
            .setMfaKeyMetadata(
              keyId = 0,
              metadata = metadata,
              svrKey = SvrKey(ByteArray(32)),
            ).await()
        assertIs<IllegalArgumentException>(assertIs<RequestResult.ApplicationError>(setResult).cause)
      }
    }

  @Test
  fun testTotpKeyCreatedAtBeforeEpoch() =
    runTest {
      val tokioAsyncContext = TokioAsyncContext()
      val (chat, _) = AuthenticatedChatConnection.fakeConnect(tokioAsyncContext, NoOpListener())
      val service = AuthAccountsService(chat)
      val svrKey = SvrKey(ByteArray(32))
      // There is no upper bound, but the bridge represents timestamps as non-negative milliseconds.
      val unsupportedCreatedAtValues =
        listOf(
          Instant.EPOCH.minusNanos(1),
          Instant.EPOCH.minusMillis(1),
          Instant.ofEpochSecond(-1),
        )

      for (createdAt in unsupportedCreatedAtValues) {
        val metadata = MfaMetadata(name = "test", createdAt = createdAt)

        val confirmResult =
          service
            .confirmTotpKey(
              oneTimePassword = 123456,
              metadata = metadata,
              svrKey = svrKey,
            ).await()
        assertIs<IllegalArgumentException>(
          assertIs<RequestResult.ApplicationError>(confirmResult).cause,
          "confirm for $createdAt",
        )

        val setResult = service.setMfaKeyMetadata(keyId = 0, metadata = metadata, svrKey = svrKey).await()
        assertIs<IllegalArgumentException>(
          assertIs<RequestResult.ApplicationError>(setResult).cause,
          "set for $createdAt",
        )
      }
    }

  @Test
  fun testMfaKeyIdOutOfRange() =
    runTest {
      val tokioAsyncContext = TokioAsyncContext()
      val (chat, _) = AuthenticatedChatConnection.fakeConnect(tokioAsyncContext, NoOpListener())
      val service = AuthAccountsService(chat)

      // -1 is below the range; 128 is the first ID past it.
      for (badId in listOf(-1, 128)) {
        val removeResult = service.removeMfaKey(keyId = badId).await()
        assertIs<IllegalArgumentException>(assertIs<RequestResult.ApplicationError>(removeResult).cause, "for $badId")
      }
    }

  @Test
  fun testListMfaKeys() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_ListMfaKeysTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, req ->
          chat.listMfaKeys(svrKey = SvrKey(req.svrKey))
        },
        check = { expected, actual ->
          when (expected) {
            is ListMfaKeysOut.Success -> {
              val keys = assertIs<RequestResult.Success<List<ConfirmedMfaKey>>>(actual).result
              assertEquals(expected._0.map { ConfirmedMfaKey.fromInternal(it) }, keys)
              for ((expectedKey, key) in expected._0.zip(keys)) {
                if (expectedKey.metadata is BridgeConfirmedMfaKeyMetadata.Unreadable) {
                  assertNull(key.metadata)
                }
                when (expectedKey.kind) {
                  BridgeMfaKeyKind.Totp -> assertEquals(MfaKeyKind.TOTP, key.kind)
                  BridgeMfaKeyKind.Unknown -> assertEquals(MfaKeyKind.UNKNOWN, key.kind)
                }
              }
            }
          }
        },
      )
    }

  @Test
  fun testSetMfaKeyMetadata() =
    runTest {
      NativeTesting.TESTING_EnableDeterministicRngForTesting()
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetMfaKeyMetadataTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, req ->
          chat.setMfaKeyMetadata(
            keyId = req.keyId,
            metadata = MfaMetadata(name = req.name, createdAt = req.createdAt),
            svrKey = SvrKey(req.svrKey),
            rngSeedForTesting = DeterministicRandomSeedUseOnlyForTesting(0),
          )
        },
        check = { expected, actual ->
          when (expected) {
            SetMfaKeyMetadataOut.Success -> assertIs<RequestResult.Success<Unit>>(actual)
            SetMfaKeyMetadataOut.KeyNotFound ->
              actual.assertNonSuccess<_, _, MfaKeyNotFoundException>()
          }
        },
      )
    }

  @Test
  fun testRemoveMfaKey() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_RemoveMfaKeyTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthAccountsService,
        invoke = { chat, req ->
          chat.removeMfaKey(keyId = req.keyId)
        },
        check = { expected, actual ->
          when (expected) {
            RemoveMfaKeyOut.Success -> assertIs<RequestResult.Success<Unit>>(actual)
          }
        },
      )
    }
}

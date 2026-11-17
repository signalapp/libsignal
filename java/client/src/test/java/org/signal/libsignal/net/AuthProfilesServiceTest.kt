//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.net.assertNonSuccess
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

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
}

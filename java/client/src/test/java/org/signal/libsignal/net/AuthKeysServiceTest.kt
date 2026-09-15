//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthKeysServiceTest {
  @Test
  fun testGetPreKeyCount() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetPreKeyCountTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthKeysService,
        invoke = { chat, req ->
          chat.getPreKeyCount()
        },
        check = { expected, actual ->
          assertEquals(
            expected,
            assertIs<RequestResult.Success<PreKeyCounts>>(actual).result,
          )
        },
      )
    }

  @Test
  fun testSetOneTimeEcPreKeys() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetOneTimeEcPreKeysTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthKeysService,
        invoke = { chat, req ->
          chat.setOneTimeEcPreKeys(
            identity = ServiceId.Kind.values()[req.identity],
            preKeys = req.preKeys.map { PublicEcPreKey(it.first, ECPublicKey(it.second)) },
          )
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testSetOneTimeKemPreKeys() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetOneTimeKemPreKeysTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthKeysService,
        invoke = { chat, req ->
          chat.setOneTimeKemPreKeys(
            identity = ServiceId.Kind.values()[req.identity],
            preKeys = req.preKeys.map { PublicKemPreKey(it.id, KEMPublicKey(it.key), it.sig) },
          )
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testSetSignedEcPreKey() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetSignedEcPreKeyTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthKeysService,
        invoke = { chat, req ->
          chat.setSignedEcPreKey(
            identity = ServiceId.Kind.values()[req.identity],
            preKey = PublicSignedEcPreKey(req.preKey.id, ECPublicKey(req.preKey.key), req.preKey.sig),
          )
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testSetLastResortKemPreKey() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetLastResortKemPreKeyTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthKeysService,
        invoke = { chat, req ->
          chat.setLastResortKemPreKey(
            identity = ServiceId.Kind.values()[req.identity],
            preKey = PublicKemPreKey(req.preKey.id, KEMPublicKey(req.preKey.key), req.preKey.sig),
          )
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }
}

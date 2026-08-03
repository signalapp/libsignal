//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.ReserveUsernameHashOut
import org.signal.libsignal.internal.SetUsernameLinkOut
import org.signal.libsignal.net.assertNonSuccess
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthUsernamesServiceTest {
  @Test
  fun testReserveUsernameHashName() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_ReserveUsernameHashTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthUsernamesService,
        invoke = { chat, req ->
          chat.reserveUsernameHash(
            usernameHashes = req.usernames,
          )
        },
        check = { expected, actual ->
          when (expected) {
            is ReserveUsernameHashOut.Success ->
              assertContentEquals(
                expected._0,
                assertIs<RequestResult.Success<UsernameHash>>(actual).result,
              )
            ReserveUsernameHashOut.UsernameNotAvailable ->
              actual.assertNonSuccess<_, _, UsernameNotAvailableException>()
          }
        },
      )
    }

  @Test
  fun testSetUsernameLink() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetUsernameLinkTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthUsernamesService,
        invoke = { chat, req ->
          chat.setUsernameLink(
            usernameCiphertext = req.usernameCiphertext,
            keepLinkHandle = req.keepLinkHandle,
          )
        },
        check = { expected, actual ->
          when (expected) {
            is SetUsernameLinkOut.Success ->
              assertEquals(
                expected._0,
                assertIs<RequestResult.Success<UUID>>(actual).result,
              )
            SetUsernameLinkOut.UsernameNotSet -> actual.assertNonSuccess<_, _, UsernameNotSetException>()
          }
        },
      )
    }

  @Test
  fun testDeleteUsernameHash() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_DeleteUsernameHashTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthUsernamesService,
        invoke = { chat, _ ->
          chat.deleteUsernameHash()
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testDeleteUsernameLink() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_DeleteUsernameLinkTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthUsernamesService,
        invoke = { chat, _ ->
          chat.deleteUsernameLink()
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }
}

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.ReserveUsernameHashOut
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertIs

class AuthUsernamesServiceTest {
  @Test
  fun testReserveUsernameHashName() {
    GrpcTestCase.runTests(
      NativeTestingNice.TESTING_ReserveUsernameHashTests(),
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
          ReserveUsernameHashOut.UsernameNotAvailable -> actual.assertNonSuccess<_, _, UsernameNotAvailableException>()
        }
      },
    )
  }
}

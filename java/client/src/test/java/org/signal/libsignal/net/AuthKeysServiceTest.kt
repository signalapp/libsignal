//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.NativeTestingNice
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
}

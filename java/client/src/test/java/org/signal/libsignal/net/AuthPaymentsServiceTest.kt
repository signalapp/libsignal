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

class AuthPaymentsServiceTest {
  @Test
  fun testGetCurrencyConversions() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetCurrencyConversionsTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthPaymentsService,
        invoke = { chat, _ ->
          chat.getCurrencyConversions()
        },
        check = { expected, actual ->
          assertEquals(expected.toPublic(), assertIs<RequestResult.Success<CurrencyConversions>>(actual).result)
        },
      )
    }
  }
}

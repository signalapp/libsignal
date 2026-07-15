//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.NativeTestingNice
import kotlin.test.Test
import kotlin.test.assertIs

class AuthAccountsServiceTest {
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
}

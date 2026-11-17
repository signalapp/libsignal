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

class AuthRemoteConfigurationServiceTest {
  @Test
  fun testGetBadges() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetBadgesTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthRemoteConfigurationService,
        invoke = { chat, req ->
          chat.getBadges(
            etag = req,
          )
        },
        check = { expected, actual ->
          assertEquals(assertIs<RequestResult.Success<TaggedBadges?>>(actual, actual.toString()).result, expected)
        },
      )
    }
  }
}

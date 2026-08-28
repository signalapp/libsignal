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

class UnauthCredentialsServiceTest {
  @Test
  fun testCheckSvrCredentials() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_CheckSvrCredentialsTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthCredentialsService,
        invoke = { chat, req ->
          chat.checkSvrCredentials(
            number = req.number,
            credentials = req.passwords,
          )
        },
        check = { expected, actual ->
          assertEquals(expected.toMap(), assertIs<RequestResult.Success<Map<String, AuthCheckResult>>>(actual).result)
        },
      )
    }
  }
}

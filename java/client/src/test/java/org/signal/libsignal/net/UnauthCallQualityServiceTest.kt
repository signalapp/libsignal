//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.NativeTestingNice
import kotlin.test.Test
import kotlin.test.assertIs

class UnauthCallQualityServiceTest {
  @Test
  fun testSubmitCallQualitySurvey() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SubmitCallQualitySurveyTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthCallQualityService,
        invoke = { chat, req ->
          chat.submitCallQualitySurvey(
            survey = req,
          )
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }
}

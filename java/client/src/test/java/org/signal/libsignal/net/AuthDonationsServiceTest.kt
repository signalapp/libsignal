//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.CreateDonationPermitsOut
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.donation.DonationPermit
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthDonationsServiceTest {
  @Test
  fun testCreateDonationPermits() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_CreateDonationPermitsTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthDonationsService,
        invoke = { chat, req ->
          chat.createDonationPermits(
            requestContext = req.requestContext,
            serverParams = ServerPublicParams(req.serverParams.bytes),
          )
        },
        check = { expected, actual ->
          when (expected) {
            is CreateDonationPermitsOut.Success ->
              assertEquals(
                expected._0,
                assertIs<RequestResult.Success<List<DonationPermit>>>(actual).result,
              )
            is CreateDonationPermitsOut.UnexpectedError ->
              assertContains(assertIs<RequestResult.ApplicationError>(actual).toString(), expected.contains)
          }
        },
      )
    }
  }
}

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.CreateDonationPermitsOut
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.RedeemDonationReceiptOut
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.donation.DonationPermit
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthDonationsServiceTest {
  @Test
  fun testRedeemDonationReceipt() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_RedeemDonationReceiptTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthDonationsService,
        invoke = { chat, req ->
          chat.redeemDonationReceipt(
            presentation = req.presentation,
            visibility = req.visibility,
          )
        },
        check = { expected, actual ->
          when (expected) {
            RedeemDonationReceiptOut.Success -> assertIs<RequestResult.Success<Unit>>(actual)
            RedeemDonationReceiptOut.InvalidReceipt -> actual.assertNonSuccess<_, _, InvalidReceiptException>()
            RedeemDonationReceiptOut.AlreadyRedeemed ->
              actual.assertNonSuccess<_, _, ReceiptAlreadyRedeemedException>()
            is RedeemDonationReceiptOut.UnexpectedError ->
              assertContains(assertIs<RequestResult.ApplicationError>(actual).toString(), expected.contains)
          }
        },
      )
    }
  }

  @Test
  fun testBadgeVisibilityOf() {
    assertEquals(BadgeVisibility.DoNotSet, BadgeVisibility.of(isVisible = false, isPrimary = false))
    assertEquals(BadgeVisibility.DoNotSet, BadgeVisibility.of(isVisible = false, isPrimary = true))
    assertEquals(BadgeVisibility.SetVisible, BadgeVisibility.of(isVisible = true, isPrimary = false))
    assertEquals(BadgeVisibility.SetPrimary, BadgeVisibility.of(isVisible = true, isPrimary = true))
  }

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

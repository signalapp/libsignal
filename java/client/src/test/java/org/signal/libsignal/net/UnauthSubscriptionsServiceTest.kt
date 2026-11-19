//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.GetSubscriptionReceiptCredentialOut
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.ReceiptCredentialError
import org.signal.libsignal.net.assertNonSuccess
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.receipts.ReceiptCredential
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs

class UnauthSubscriptionsServiceTest {
  @Test
  fun testGetReceiptCredential() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetSubscriptionReceiptCredentialTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthSubscriptionsService,
        invoke = { chat, req ->
          chat.getReceiptCredential(
            subscriberId = req.subscriberId,
            receiptCredentialRequestContext = req.receiptCredentialRequestContext,
            serverParams = ServerPublicParams(req.serverParams.bytes),
          )
        },
        check = { expected, actual ->
          when (expected) {
            is GetSubscriptionReceiptCredentialOut.ExplicitError -> {
              when (expected._0) {
                ReceiptCredentialError.PaymentNotFound -> {
                  actual
                    .assertNonSuccess<_, _, ReceiptCredentialException.PaymentNotFound>()
                }

                is ReceiptCredentialError.PaymentRequired -> {
                  assertEquals(
                    expected._0.chargeFailure.firstOrNull(),
                    actual
                      .assertNonSuccess<_, _, ReceiptCredentialException.PaymentRequired>()
                      .chargeFailure,
                  )
                }

                ReceiptCredentialError.PaymentStillProcessing -> {
                  actual
                    .assertNonSuccess<_, _, ReceiptCredentialException.PaymentStillProcessing>()
                }

                ReceiptCredentialError.ReceiptAlreadyIssued -> {
                  actual
                    .assertNonSuccess<_, _, ReceiptCredentialException.ReceiptAlreadyIssued>()
                }
              }
            }

            is GetSubscriptionReceiptCredentialOut.Success -> {
              assertEquals(
                expected._0,
                assertIs<RequestResult.Success<ReceiptCredential>>(actual).result,
              )
            }

            is GetSubscriptionReceiptCredentialOut.UnexpectedError -> {
              assertContains(assertIs<RequestResult.ApplicationError>(actual).toString(), expected.contains)
            }
          }
        },
      )
    }
  }

  @Test
  fun testGetPurchaseProductConfiguration() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetProductConfigurationTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthSubscriptionsService,
        invoke = { chat, req -> chat.getPurchaseProductConfiguration() },
        check = { expected, actual ->
          assertEquals(
            expected,
            assertIs<RequestResult.Success<PurchaseProductConfiguration>>(actual).result,
          )
        },
      )
    }
}

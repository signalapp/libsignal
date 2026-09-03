//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.CreateLoginReceiptCredentialOut
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.ReceiptCredentialError
import org.signal.libsignal.net.assertNonSuccess
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.receipts.ReceiptCredential
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs

class UnauthLoginPurchaseServiceTest {
  @Test
  fun testCreateLoginReceiptCredential() {
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_CreateLoginReceiptCredentialTests(),
        { tokio, listener ->
          UnauthenticatedChatConnection.fakeConnect(tokio, listener, Network.Environment.STAGING)
        },
        ::UnauthLoginPurchaseService,
        invoke = { chat, req ->
          chat.createLoginReceiptCredential(
            paymentProcessor = req.paymentProcessor,
            purchaseIdentifier = req.purchaseIdentifier,
            receiptCredentialRequestContext = req.receiptCredentialRequestContext,
            serverParams = ServerPublicParams(req.serverParams.bytes),
            purchaseTime = req.purchaseTime,
          )
        },
        check = { expected, actual ->
          when (expected) {
            is CreateLoginReceiptCredentialOut.ExplicitError ->
              when (expected._0) {
                ReceiptCredentialError.PaymentNotFound ->
                  actual
                    .assertNonSuccess<_, _, CreateLoginReceiptCredentialException.PaymentNotFound>()
                is ReceiptCredentialError.PaymentRequired ->
                  assertEquals(
                    expected._0.chargeFailure.firstOrNull(),
                    actual
                      .assertNonSuccess<_, _, CreateLoginReceiptCredentialException.PaymentRequired>()
                      .chargeFailure,
                  )
                ReceiptCredentialError.PaymentStillProcessing ->
                  actual
                    .assertNonSuccess<_, _, CreateLoginReceiptCredentialException.PaymentStillProcessing>()
                ReceiptCredentialError.ReceiptAlreadyIssued ->
                  actual
                    .assertNonSuccess<_, _, CreateLoginReceiptCredentialException.ReceiptAlreadyIssued>()
              }
            is CreateLoginReceiptCredentialOut.Success ->
              assertEquals(
                expected._0,
                assertIs<RequestResult.Success<ReceiptCredential>>(actual).result,
              )
            is CreateLoginReceiptCredentialOut.UnexpectedError ->
              assertContains(assertIs<RequestResult.ApplicationError>(actual).toString(), expected.contains)
          }
        },
      )
    }
  }
}

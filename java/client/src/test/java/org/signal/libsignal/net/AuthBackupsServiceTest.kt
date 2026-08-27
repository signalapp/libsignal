//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.RedeemBackupReceiptOut
import org.signal.libsignal.net.assertNonSuccess
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialPresentation
import kotlin.test.Test
import kotlin.test.assertIs

class AuthBackupsServiceTest {
  @Test
  fun testRedeemReceipt() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_RedeemBackupReceiptTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthBackupsService,
        invoke = { chat, presentation ->
          chat.redeemReceipt(
            presentation = ReceiptCredentialPresentation(presentation),
          )
        },
        check = { expected, actual ->
          when (expected) {
            RedeemBackupReceiptOut.Success -> assertIs<RequestResult.Success<Unit>>(actual)
            RedeemBackupReceiptOut.InvalidReceipt -> actual.assertNonSuccess<_, _, InvalidReceiptException>()
            RedeemBackupReceiptOut.MissingBackupId -> actual.assertNonSuccess<_, _, MissingBackupIdException>()
            RedeemBackupReceiptOut.MissingResponse ->
              assertIs<UnexpectedResponseException>(
                assertIs<RequestResult.ApplicationError>(actual).cause,
              )
          }
        },
      )
    }
}

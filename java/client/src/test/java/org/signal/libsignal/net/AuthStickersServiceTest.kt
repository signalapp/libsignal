//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.GetStickerUploadFormsOut
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.net.assertNonSuccess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthStickersServiceTest {
  @Test
  fun testGetStickerUploadForms() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetStickerUploadFormTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthStickersService,
        invoke = { chat, req ->
          chat.getStickerUploadForms(
            numberOfStickers = req,
          )
        },
        check = { expected, actual ->
          when (expected) {
            is GetStickerUploadFormsOut.Success ->
              assertEquals(
                expected._0,
                assertIs<RequestResult.Success<GetStickerUploadFormsResponse>>(actual).result,
              )
            GetStickerUploadFormsOut.Invalid ->
              assertIs<UnexpectedResponseException>(
                assertIs<RequestResult.ApplicationError>(actual).cause,
              )
          }
        },
      )
    }
}

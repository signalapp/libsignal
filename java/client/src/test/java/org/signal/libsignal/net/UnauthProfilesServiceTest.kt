//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.junit.Assert.assertEquals
import org.junit.Test
import org.signal.libsignal.internal.TokioAsyncContext
import org.signal.libsignal.protocol.ServiceId
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.arrayOf
import kotlin.test.assertIs

class UnauthProfilesServiceTest {
  @Test
  fun testAccountExists() {
    data class TestCase(
      val serviceId: ServiceId,
      val found: Boolean,
    )

    val aci = ServiceId.Aci(UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"))
    val pni = ServiceId.Pni(UUID.fromString("796abedb-ca4e-4f18-8803-1fde5b921f9f"))

    val tokioAsyncContext = TokioAsyncContext()
    val (chat, fakeRemote) =
      UnauthenticatedChatConnection.fakeConnect(
        tokioAsyncContext,
        NoOpListener(),
        Network.Environment.STAGING,
      )

    val profilesService = UnauthProfilesService(chat)

    for (testCase in listOf(
      TestCase(aci, true),
      TestCase(pni, true),
      TestCase(aci, false),
      TestCase(pni, false),
    )) {
      val responseFuture = profilesService.accountExists(testCase.serviceId)
      val (request, requestId) = fakeRemote.getNextIncomingRequest().get(1, TimeUnit.SECONDS)
      assertEquals("HEAD", request.method)
      assertEquals("/v1/accounts/account/${testCase.serviceId.toServiceIdString()}", request.pathAndQuery)
      fakeRemote.sendResponse(
        requestId,
        if (testCase.found) 200 else 404,
        if (testCase.found) "OK" else "Not Found",
        arrayOf(),
        ByteArray(0),
      )
      val result = responseFuture.get()
      val successResult = assertIs<RequestResult.Success<Boolean>>(result)
      assertEquals(testCase.found, successResult.result)
    }
  }
}

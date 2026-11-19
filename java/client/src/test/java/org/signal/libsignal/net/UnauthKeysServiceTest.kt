//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.GetPreKeysOut
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.TestingUserBasedAuthorization
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class UnauthKeysServiceTest {
  @Test
  fun testGetPreKeys() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetPreKeysTests(),
        newConnection = { tokioAsyncContext, listener ->
          UnauthenticatedChatConnection.fakeConnect(
            tokioAsyncContext,
            listener,
            Network.Environment.STAGING,
          )
        },
        ::UnauthKeysService,
        invoke = { service, request ->
          val auth =
            when (val auth = request.auth) {
              is TestingUserBasedAuthorization.AccessKey -> UserBasedAuthorization.AccessKey(auth.key)
              is TestingUserBasedAuthorization.GroupSendToken ->
                UserBasedAuthorization.GroupSend(GroupSendFullToken(auth.token))
              TestingUserBasedAuthorization.Unrestricted -> UserBasedAuthorization.UnrestrictedUnauthenticatedAccess
            }
          service.getPreKeys(
            request.target,
            if (request.deviceId < 0) DeviceSpecifier.AllDevices else DeviceSpecifier.SpecificDevice(request.deviceId),
            auth,
          )
        },
        check = { expected, actual ->
          when (expected) {
            is GetPreKeysOut.Success -> {
              val (identityKey, bundles) =
                assertIs<RequestResult.Success<Pair<IdentityKey, List<PreKeyBundle>>>>(actual).result
              assertContentEquals(expected.identityKey, identityKey.serialize())
              assertEquals(expected.bundleCount, bundles.size)
            }
            GetPreKeysOut.NotFound ->
              assertIs<ServiceIdNotFoundException>(assertIs<RequestResult.NonSuccess<GetPreKeysError>>(actual).error)
            GetPreKeysOut.Unauthorized ->
              assertIs<RequestUnauthorizedException>(assertIs<RequestResult.NonSuccess<GetPreKeysError>>(actual).error)
            GetPreKeysOut.Unexpected -> assertIs<RequestResult.ApplicationError>(actual)
          }
        },
      )
    }
}

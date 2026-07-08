//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import kotlinx.coroutines.test.runTest
import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.RemoveDeviceOut
import org.signal.libsignal.internal.SetDeviceNameOut
import org.signal.libsignal.net.assertNonSuccess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthDevicesServiceTest {
  @Test
  fun testSetDeviceName() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetDeviceNameTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthDevicesService,
        invoke = { chat, req ->
          chat.setDeviceName(
            deviceId = req.id,
            encryptedName = req.encryptedName,
          )
        },
        check = { expected, actual ->
          when (expected) {
            SetDeviceNameOut.Success -> assertIs<RequestResult.Success<Unit>>(actual)
            SetDeviceNameOut.DeviceNotFound -> actual.assertNonSuccess<_, _, DeviceIdNotFoundException>()
          }
        },
      )
    }

  @Test
  fun testSetPushTokenFcm() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_SetPushTokenFcmTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthDevicesService,
        invoke = { chat, req ->
          chat.setPushToken(fcmToken = req)
        },
        check = { _, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }

  @Test
  fun testRemoveDevice() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_RemoveDeviceTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthDevicesService,
        invoke = { chat, req ->
          chat.removeDevice(deviceId = req.id)
        },
        check = { expected, actual ->
          when (expected) {
            RemoveDeviceOut.Success -> assertIs<RequestResult.Success<Unit>>(actual)
          }
        },
      )
    }

  @Test
  fun testGetDevices() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_GetDevicesTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthDevicesService,
        invoke = { chat, req ->
          chat.getDevices()
        },
        check = { expected, actual ->
          assertEquals(
            expected.devices.map(LinkedDevice::fromInternal),
            assertIs<RequestResult.Success<List<LinkedDevice>>>(actual).result,
          )
        },
      )
    }

  @Test
  fun testClearPushToken() =
    runTest {
      GrpcTestCase.runTests(
        NativeTestingNice.TESTING_ClearPushTokenTests(),
        AuthenticatedChatConnection::fakeConnect,
        ::AuthDevicesService,
        invoke = { chat, req ->
          chat.clearPushToken()
        },
        check = { expected, actual ->
          assertIs<RequestResult.Success<Unit>>(actual)
        },
      )
    }
}

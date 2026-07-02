//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.NativeTestingNice
import org.signal.libsignal.internal.SetDeviceNameOut
import org.signal.libsignal.net.assertNonSuccess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthDevicesServiceTest {
  @Test
  fun testSetDeviceName() {
    GrpcTestCase.runTests(
      NativeTestingNice.TESTING_SetDeviceNameTests(),
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
  fun testGetDevices() {
    GrpcTestCase.runTests(
      NativeTestingNice.TESTING_GetDevicesTests(),
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
}

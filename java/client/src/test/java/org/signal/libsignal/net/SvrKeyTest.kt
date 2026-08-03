//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.protocol.util.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

class SvrKeyTest {
  private val svrKey = SvrKey(ByteArray(SvrKey.SIZE) { 0x2a })

  @Test
  fun testDerivations() {
    // These known answers were taken from iOS' MasterKeyTest.testDerivedKeys.
    // See: https://github.com/signalapp/Signal-iOS/blob/265ee500/SignalServiceKit/tests/Account/MasterKeyTest.swift#L54
    assertEquals(
      "3a40e25812e6c20cca76a602451dd2bc7484553514438cade320c2aef54e10d1",
      Hex.toStringCondensed(svrKey.deriveRegistrationLock()),
    )
    assertEquals(
      "91f959cfee39676dedd028bc8bbbd1e91ffa6a42c57754d095fe8abe7f0d4f56",
      Hex.toStringCondensed(svrKey.deriveRegistrationRecoveryPassword()),
    )
    assertEquals(
      "3f31b618172a9f8ad45e290788e6176736e6161d4ea0e8050f8553521f59c200",
      Hex.toStringCondensed(svrKey.deriveStorageServiceKey()),
    )
    assertEquals(
      "cd2a39f4857de4df3fe793d1de061bfa3dd63533c0a4ef79b3fa3eba2bf96e62",
      Hex.toStringCondensed(svrKey.deriveLoggingKey()),
    )
  }
}

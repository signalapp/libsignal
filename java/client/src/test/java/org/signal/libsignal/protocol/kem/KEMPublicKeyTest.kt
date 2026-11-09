//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class KEMPublicKeyTest {
  @Test
  fun testDeserializeWithOffsetAndLength() {
    val key = KEMKeyPair.generate(KEMKeyType.KYBER_1024).publicKey
    val serialized = key.serialize()
    val withPrefix = byteArrayOf(0) + serialized

    assertEquals(key, KEMPublicKey(withPrefix, 1, serialized.size))
    assertFailsWith<IllegalArgumentException> { KEMPublicKey(withPrefix, 1, withPrefix.size) }
    assertFailsWith<IllegalArgumentException> { KEMPublicKey(withPrefix, withPrefix.size + 1, 0) }
  }
}

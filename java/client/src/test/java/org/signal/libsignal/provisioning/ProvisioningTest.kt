//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.provisioning

import org.junit.Test
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidMessageException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProvisioningTest {
  @Test
  fun testRoundTrip() {
    val secondary = RecvProvisionCiphertextState.generate()
    val pubkeyBytes = secondary.publicKey.serialize()
    assertEquals(33, pubkeyBytes.size)
    assertEquals(0x05, pubkeyBytes[0].toInt())

    val message = "provision message".toByteArray()
    val envelope = Provisioning.encryptProvisionMessage(ProvisioningPublicKey(pubkeyBytes), message)
    assertContentEquals(message, secondary.decryptEnvelope(envelope))
  }

  @Test
  fun testWrongRecipient() {
    val secondary = RecvProvisionCiphertextState.generate()
    val other = RecvProvisionCiphertextState.generate()
    val envelope = Provisioning.encryptProvisionMessage(secondary.publicKey, byteArrayOf(1, 2, 3))
    assertFailsWith<InvalidMessageException> { other.decryptEnvelope(envelope) }
  }

  @Test
  fun testMalformedEnvelope() {
    val secondary = RecvProvisionCiphertextState.generate()
    assertFailsWith<InvalidMessageException> { secondary.decryptEnvelope(byteArrayOf(0xff.toByte())) }
    assertFailsWith<InvalidMessageException> { secondary.decryptEnvelope(byteArrayOf()) }
  }

  @Test
  fun testBadPublicKey() {
    val pubkeyBytes = RecvProvisionCiphertextState.generate().publicKey.serialize()
    for (badLength in listOf(pubkeyBytes.copyOf(32), pubkeyBytes.copyOf(34))) {
      assertFailsWith<InvalidKeyException> {
        Provisioning.encryptProvisionMessage(ProvisioningPublicKey(badLength), byteArrayOf())
      }
    }
    pubkeyBytes[0] = 0x06
    assertFailsWith<InvalidKeyException> {
      Provisioning.encryptProvisionMessage(ProvisioningPublicKey(pubkeyBytes), byteArrayOf())
    }
  }
}

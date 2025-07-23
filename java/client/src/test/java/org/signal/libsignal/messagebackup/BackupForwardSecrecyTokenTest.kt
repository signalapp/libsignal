//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.signal.libsignal.zkgroup.InvalidInputException

class BackupForwardSecrecyTokenTest {
  @Test
  fun testValidTokenCreation() {
    val validBytes = ByteArray(32) { 0x42 }
    val token = BackupForwardSecrecyToken(validBytes)
    assertNotNull(token)
    assertEquals(32, token.serialize().size)

    val retrievedBytes = token.serialize()
    assertArrayEquals(validBytes, retrievedBytes)
  }

  @Test(expected = InvalidInputException::class)
  fun testInvalidTokenCreationTooShort() {
    val invalidBytes = ByteArray(31) { 0x42 }
    BackupForwardSecrecyToken(invalidBytes)
  }

  @Test(expected = InvalidInputException::class)
  fun testInvalidTokenCreationTooLong() {
    val invalidBytes = ByteArray(33) { 0x42 }
    BackupForwardSecrecyToken(invalidBytes)
  }

  @Test
  fun testRoundTripSerialization() {
    // Use different hardcoded pattern to ensure we're not just getting lucky
    val originalBytes = ByteArray(32) { index -> (index % 256).toByte() }
    val token = BackupForwardSecrecyToken(originalBytes)

    val serialized = token.serialize()
    val reconstructedToken = BackupForwardSecrecyToken(serialized)

    assertNotNull(reconstructedToken)
    assertEquals(32, reconstructedToken.serialize().size)

    val reconstructedBytes = reconstructedToken.serialize()
    assertArrayEquals(originalBytes, reconstructedBytes)
  }
}

//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup

import org.signal.libsignal.zkgroup.donation.DonationPermit
import org.signal.libsignal.zkgroup.donation.DonationPermitDerivedKeyPair
import org.signal.libsignal.zkgroup.donation.DonationPermitRequestContext
import org.signal.libsignal.zkgroup.donation.DonationPermitResponse
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DonationPermitTest {
  private val secret = ServerSecretParams.generate()
  private val public = secret.publicParams
  private val now = Instant.ofEpochSecond(1_600_000_000)
  private val expiration = DonationPermitResponse.defaultExpiration(now)
  private val keyPair = DonationPermitDerivedKeyPair.forExpiration(expiration, secret)

  private fun issuePermits(count: Int): List<DonationPermit> {
    val context = DonationPermitRequestContext.forCount(count)
    val request = context.request()
    assertEquals(count, request.permitCount)
    val response = request.issue(keyPair)
    assertEquals(response.expiration, expiration)
    val permits = context.receive(response, public, now)
    assertEquals(permits.map { it.spendId.toList() }.distinct().size, permits.size)
    return permits
  }

  private fun issueOnePermit(): DonationPermit = issuePermits(1).single()

  @Test
  fun defaultFlow() {
    for (count in listOf(3, 10, 100)) {
      val permits = issuePermits(count)
      assertEquals(permits.size, count)
      for (permit in permits) {
        permit.verify(keyPair, now)
        assertEquals(permit.expiration, expiration)
      }
    }
  }

  @Test
  fun wrongKeyFails() {
    val permit = issueOnePermit()
    val otherSecret = ServerSecretParams.generate()
    val wrongKey = DonationPermitDerivedKeyPair.forExpiration(expiration, otherSecret)
    assertFailsWith(VerificationFailedException::class) {
      permit.verify(wrongKey, now)
    }
  }

  @Test
  fun expiredPermitFails() {
    val permit = issueOnePermit()
    val afterExpiry = expiration.plusSeconds(1)
    assertFailsWith(VerificationFailedException::class) { permit.verify(keyPair, afterExpiry) }
  }
}

//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Before
import org.junit.ClassRule
import org.junit.Test
import org.signal.libsignal.internal.CalledFromNative
import org.signal.libsignal.internal.NativeTesting
import org.signal.libsignal.messagebackup.BackupForwardSecrecyToken
import org.signal.libsignal.messagebackup.BackupKey
import org.signal.libsignal.protocol.ServiceId.Aci
import org.signal.libsignal.protocol.logging.Log
import org.signal.libsignal.protocol.util.Hex
import org.signal.libsignal.util.TestEnvironment
import org.signal.libsignal.util.TestLogger
import java.util.concurrent.TimeUnit
import kotlin.getOrThrow

class SecureValueRecoveryBackupTest {
  companion object {
    private const val TEST_INVALID_SECRET_DATA = "invalid secret data"
    private const val EXPECTED_ERROR_MESSAGE = "Invalid data from previous backup"
    private const val ASYNC_TIMEOUT_SECONDS = 10L
    private val TEST_ACI = Aci.parseFromString("e74beed0-e70f-4cfd-abbb-7e3eb333bbac")

    @ClassRule @JvmField
    val logger = TestLogger()
  }

  private lateinit var testBackupKey: BackupKey
  private lateinit var testInvalidSecretData: ByteArray
  private lateinit var net: Network
  private lateinit var svrB: SvrB
  private lateinit var testUsername: String
  private lateinit var testPassword: String
  private var currentTestIsNonHermetic = false

  @Before
  fun setUp() {
    testBackupKey = BackupKey.generateRandom()
    testInvalidSecretData = TEST_INVALID_SECRET_DATA.toByteArray()
    net = Network(Network.Environment.STAGING, "test")
    val authSecret = System.getenv("LIBSIGNAL_TESTING_SVRB_ENCLAVE_SECRET")
    if (authSecret != null) {
      testUsername = Hex.toStringCondensed(testBackupKey.deriveBackupId(TEST_ACI))
      testPassword = NativeTesting.TESTING_CreateOTPFromBase64(testUsername, authSecret)
    } else {
      testUsername = System.getenv("LIBSIGNAL_TESTING_SVRB_USERNAME") ?: ""
      testPassword = System.getenv("LIBSIGNAL_TESTING_SVRB_PASSWORD") ?: ""
    }
    svrB = net.svrB(testUsername, testPassword)
  }

  @After
  fun tearDown() {
    if (currentTestIsNonHermetic) {
      try {
        // As a best effort, try to clean up after ourselves
        // so we don't use up a ton of space on the server.
        svrB.remove().get(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS)
      } catch (e: Exception) {
        Log.w("SecureValueRecoveryBackupTest", "remove failed", e)
      }
    }
  }

  private fun checkNonHermetic() {
    val enableTest = TestEnvironment.get("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS")
    Assume.assumeNotNull(enableTest)
    currentTestIsNonHermetic = true
  }

  private fun makeStoreResponse(previousSecretData: ByteArray? = null): SvrBStoreResponse =
    svrB
      .store(testBackupKey, previousSecretData ?: svrB.createNewBackupChain(testBackupKey))
      .get(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS)
      .getOrThrow()

  private fun assertValidToken(token: BackupForwardSecrecyToken) {
    val tokenBytes = token.serialize()
    assertEquals(BackupForwardSecrecyToken.SIZE, tokenBytes.size)

    BackupForwardSecrecyToken(tokenBytes)
  }

  @Test
  fun testStoreReturnsValidResponse() {
    checkNonHermetic()
    Assume.assumeTrue(testUsername.isNotEmpty() && testPassword.isNotEmpty())

    val response = makeStoreResponse()

    val token = response.forwardSecrecyToken
    assertNotNull(token)
    assertValidToken(token)

    val metadata = response.metadata
    assertFalse(metadata.isEmpty())

    val nextSecretData = response.nextBackupSecretData
    assertFalse(nextSecretData.isEmpty())
  }

  @Test
  fun testBackupForwardSecrecyTokenSerializesAndDeserializesCorrectly() {
    checkNonHermetic()
    Assume.assumeTrue(testUsername.isNotEmpty() && testPassword.isNotEmpty())

    val response = makeStoreResponse()
    val token = response.forwardSecrecyToken

    assertNotNull(token)
    assertValidToken(token)
  }

  @Test
  fun testStoreWithInvalidPreviousSecretDataReturnsFailure() {
    val result = svrB.store(testBackupKey, testInvalidSecretData).get(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS)

    assertTrue("Expected failure result", result.isFailure)
    val exception = result.exceptionOrNull()
    assertNotNull("Expected exception in result", exception)

    val message = exception!!.message
    assertNotNull("Expected exception message", message)
    assertEquals("Expected error message", EXPECTED_ERROR_MESSAGE, message)
  }

  @Test
  @CalledFromNative
  fun testFullBackupFlowWithPreviousSecretData() {
    checkNonHermetic()
    Assume.assumeTrue(testUsername.isNotEmpty() && testPassword.isNotEmpty())

    // First backup without previous data
    val initialSecretData = svrB.createNewBackupChain(testBackupKey)
    val firstStoreResult = svrB.store(testBackupKey, initialSecretData).get(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS)
    assertTrue("First store should succeed", firstStoreResult.isSuccess)
    val firstResponse = firstStoreResult.getOrThrow()
    assertNotNull("First response should not be null", firstResponse)

    val firstToken = firstResponse.forwardSecrecyToken
    assertNotNull("First forward secrecy token should not be null", firstToken)
    assertValidToken(firstToken)

    val firstSecretData = firstResponse.nextBackupSecretData
    assertFalse(firstSecretData.isEmpty())

    val firstRestoreResult =
      svrB
        .restore(
          testBackupKey,
          firstResponse.metadata,
        ).get(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS)

    assertTrue("First restore should succeed", firstRestoreResult.isSuccess)
    val restoredFirst = firstRestoreResult.getOrThrow()
    assertNotNull("Restored first token should not be null", restoredFirst)

    val firstTokenBytes = firstToken.serialize()
    val restoredFirstTokenBytes = restoredFirst.forwardSecrecyToken.serialize()
    assertTrue(
      "Restored first token should match stored token",
      firstTokenBytes.contentEquals(restoredFirstTokenBytes),
    )

    // Second backup with previous secret data
    val secondStoreResult = svrB.store(testBackupKey, firstSecretData).get(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS)
    assertTrue("Second store should succeed", secondStoreResult.isSuccess)
    val secondResponse = secondStoreResult.getOrThrow()
    assertNotNull("Second response should not be null", secondResponse)

    val secondToken = secondResponse.forwardSecrecyToken
    assertNotNull("Second forward secrecy token should not be null", secondToken)
    assertValidToken(secondToken)

    // Should also have next secret data for future backups
    val secondSecretData = secondResponse.nextBackupSecretData
    assertFalse(secondSecretData.isEmpty())

    val secondRestoreResult =
      svrB
        .restore(
          testBackupKey,
          secondResponse.metadata,
        ).get(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS)

    assertTrue("Second restore should succeed", secondRestoreResult.isSuccess)
    val restoredSecond = secondRestoreResult.getOrThrow()
    assertNotNull("Restored second token should not be null", restoredSecond)

    val secondTokenBytes = secondToken.serialize()
    val restoredSecondTokenBytes = restoredSecond.forwardSecrecyToken.serialize()
    assertTrue(
      "Restored second token should match stored token",
      secondTokenBytes.contentEquals(restoredSecondTokenBytes),
    )

    // The tokens should be different between backups
    assertFalse(
      "First and second tokens should be different",
      firstTokenBytes.contentEquals(secondTokenBytes),
    )
  }
}

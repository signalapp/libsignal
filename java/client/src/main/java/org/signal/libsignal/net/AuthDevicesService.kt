//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.LinkedDeviceInternal
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.DeviceId
import java.time.Instant

public data class LinkedDevice(
  /**
   * The identifier for the device within an account
   */
  val id: DeviceId,
  /**
   * A sequence of bytes that encodes an encrypted human-readable name for
   * this device.
   */
  val encryptedName: ByteArray,
  /**
   * The approximate time at which this device last connected to the server.
   */
  val lastSeen: Instant,
  /**
   * The registration ID of the given device.
   */
  val registrationId: Int,
  /**
   * A sequence of bytes that encodes the time, in milliseconds, since the epoch, at which this
   * device was attached to its parent account.
   */
  val createdAtCiphertext: ByteArray,
) {
  // These need to be public for testing
  public companion object {
    public fun fromInternal(it: LinkedDeviceInternal): LinkedDevice =
      LinkedDevice(
        id = it.id,
        encryptedName = it.encryptedName,
        lastSeen = it.lastSeen,
        registrationId = it.registrationId,
        createdAtCiphertext = it.createdAtCiphertext,
      )
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as LinkedDevice

    if (id != other.id) return false
    if (lastSeen != other.lastSeen) return false
    if (registrationId != other.registrationId) return false
    if (!encryptedName.contentEquals(other.encryptedName)) return false
    if (!createdAtCiphertext.contentEquals(other.createdAtCiphertext)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = id
    result = 31 * result + lastSeen.hashCode()
    result = 31 * result + registrationId
    result = 31 * result + encryptedName.contentHashCode()
    result = 31 * result + createdAtCiphertext.contentHashCode()
    return result
  }
}

public class AuthDevicesService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Set the name of the given device ID to the provided encrypted name.
   *
   * @param encryptedName Must be between 1 and 225 bytes long
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [DeviceIdNotFoundException] indicates the recipient
   * device specified by `deviceId` could not be found.
   */
  public fun setDeviceName(
    deviceId: DeviceId,
    encryptedName: ByteArray,
  ): CompletableFuture<RequestResult<Unit, DeviceIdNotFoundException>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_device_name(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          deviceId = deviceId,
          encryptedName = encryptedName,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult<DeviceIdNotFoundException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Remove a linked device from the current account.
   *
   * Linked devices may only remove themselves, and primary devices may remove any device other
   * than themselves; the server rejects anything else as a programmer error.
   *
   * Removing a device ID that is not on the account also succeeds, so a caller retrying a removal
   * sees the same result as the original call. This is not true idempotency, though: device IDs are
   * small and get reused, so if a new device is linked and assigned [deviceId] between two calls,
   * the second call removes that new device.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun removeDevice(
    deviceId: org.signal.libsignal.protocol.DeviceId,
  ): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_remove_device(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          deviceId = deviceId,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * List the devices associated with the current account.
   */
  public fun getDevices(): CompletableFuture<RequestResult<List<LinkedDevice>, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_get_devices(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it.map(LinkedDevice::fromInternal)) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Sets the FCM push token the server should use to send new message notifications to the
   * authenticated device.
   *
   * @param fcmToken Must not be empty
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun setPushToken(fcmToken: String): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_push_token_fcm(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          fcmToken = fcmToken,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Remove any push tokens associated with the current device.
   *
   * After this call, the server will assume the current device will periodically poll for new
   * messages.
   */
  public fun clearPushToken(): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_clear_push_token(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

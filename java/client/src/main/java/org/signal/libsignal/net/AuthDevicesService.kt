//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

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
    deviceId: Int,
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
}

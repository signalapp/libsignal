//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.ServiceId

public class AuthMessagesService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Get an attachment upload form
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [UploadTooLargeException] means that the uploadSize was
   * too large.
   */
  public fun getUploadForm(uploadSize: Long): CompletableFuture<RequestResult<UploadForm, UploadTooLargeException>> =
    try {
      require(uploadSize >= 0, { "uploadSize ($uploadSize) wasn't >= 0" })
      connection.runWithContextAndConnectionHandles { asyncCtx, conn ->
        Native
          .AuthenticatedChatConnection_get_upload_form(
            asyncCtx,
            conn,
            uploadSize,
          ).mapWithCancellation(
            onSuccess = { RequestResult.Success(it as UploadForm) },
            onError = { err -> err.toRequestResult<UploadTooLargeException>() },
          )
      }
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Sends an unsealed 1:1 message.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [MismatchedDeviceException] indicates the recipient
   * devices specified in `contents` are out of date in some way. (This is not a "partial success"
   * result; the message has not been sent to anybody.) A [ServiceIdNotFoundException] indicates the
   * destination account has been unregistered. A [RateLimitChallengeException] must be handled
   * before the client can send this message.
   */
  public fun sendMessage(
    destination: ServiceId,
    timestamp: Long,
    contents: List<SingleOutboundUnsealedMessage>,
    onlineOnly: Boolean,
    urgent: Boolean,
  ): CompletableFuture<RequestResult<Unit, UnsealedSendFailure>> =
    try {
      val deviceIds = IntArray(contents.size)
      val registrationIds = IntArray(contents.size)
      val messages = arrayOfNulls<Object>(contents.size)

      contents.forEachIndexed { i, next ->
        deviceIds[i] = next.deviceId
        registrationIds[i] = next.registrationId
        messages[i] = next.message as Object
      }

      connection
        .runWithContextAndConnectionHandles { asyncCtx, conn ->
          Native.AuthenticatedChatConnection_send_message_java(
            asyncCtx,
            conn,
            destination.toServiceIdFixedWidthBinary(),
            timestamp,
            deviceIds,
            registrationIds,
            messages.requireNoNulls(),
            onlineOnly,
            urgent,
          )
        }.mapWithCancellation(
          onSuccess = { _ -> RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult<UnsealedSendFailure>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Sends a 1:1 message to linked devices.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [MismatchedDeviceException] indicates the recipient
   * devices specified in `contents` are out of date in some way. (This is not a "partial success"
   * result; the message has not been sent to anybody.) A [RateLimitChallengeException] must be
   * handled before the client can send this message.
   */
  public fun sendSyncMessage(
    timestamp: Long,
    contents: List<SingleOutboundUnsealedMessage>,
    urgent: Boolean,
  ): CompletableFuture<RequestResult<Unit, SyncSendFailure>> =
    try {
      val deviceIds = IntArray(contents.size)
      val registrationIds = IntArray(contents.size)
      val messages = arrayOfNulls<Object>(contents.size)

      contents.forEachIndexed { i, next ->
        deviceIds[i] = next.deviceId
        registrationIds[i] = next.registrationId
        messages[i] = next.message as Object
      }

      connection
        .runWithContextAndConnectionHandles { asyncCtx, conn ->
          Native.AuthenticatedChatConnection_send_sync_message_java(
            asyncCtx,
            conn,
            timestamp,
            deviceIds,
            registrationIds,
            messages.requireNoNulls(),
            urgent,
          )
        }.mapWithCancellation(
          onSuccess = { _ -> RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult<SyncSendFailure>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

/** Either [ServiceIdNotFoundException], [RateLimitChallengeException], or [MismatchedDeviceException]. */
public sealed interface UnsealedSendFailure : BadRequestError

/** Either [RateLimitChallengeException] or [MismatchedDeviceException]. */
public sealed interface SyncSendFailure : BadRequestError

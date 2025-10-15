//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.metadata.SealedSessionCipher
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken

public class UnauthMessagesService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Sends a multi-recipient message encrypted with Sealed Sender v2.
   *
   * Messages to accounts that have been unregistered will be dropped by the server and (if using
   * [MultiRecipientSendAuthorization.GroupSend]) reported in the resulting
   * [MultiRecipientMessageResponse].
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means `auth` is not valid
   * for the recipients specified in `payload`; this cannot happen when `auth` is
   * [MultiRecipientSendAuthorization.Story]. A [MismatchedDeviceException] indicates the recipient
   * devices specified in `payload` are out of date in some way. (This is not a "partial success"
   * result; the message has not been sent to anybody.)
   *
   * @see [SealedSessionCipher.multiRecipientEncrypt]
   */
  public fun sendMultiRecipientMessage(
    payload: ByteArray,
    timestamp: Long,
    auth: MultiRecipientSendAuthorization,
    onlineOnly: Boolean,
    urgent: Boolean,
  ): CompletableFuture<RequestResult<MultiRecipientMessageResponse, MultiRecipientSendFailure>> =
    try {
      connection
        .runWithContextAndConnectionHandles { asyncCtx, conn ->
          Native.UnauthenticatedChatConnection_send_multi_recipient_message(
            asyncCtx,
            conn,
            payload,
            timestamp,
            auth.groupSendTokenBytesOrNull(),
            onlineOnly,
            urgent,
          )
        }.mapWithCancellation(
          onSuccess = { rawUnregisteredIds ->
            @Suppress("UNCHECKED_CAST") // https://youtrack.jetbrains.com/issue/KT-11948
            RequestResult.Success(MultiRecipientMessageResponse(rawUnregisteredIds as Array<ByteArray>))
          },
          onError = { err -> err.toRequestResult<MultiRecipientSendFailure>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

public sealed interface MultiRecipientSendAuthorization {
  public object Story : MultiRecipientSendAuthorization

  public data class GroupSend(
    public val token: GroupSendFullToken,
  ) : MultiRecipientSendAuthorization
}

/** Either [RequestUnauthorizedException] or [MismatchedDeviceException]. */
public sealed interface MultiRecipientSendFailure : BadRequestError

private fun MultiRecipientSendAuthorization.groupSendTokenBytesOrNull(): ByteArray? =
  when (this) {
    is MultiRecipientSendAuthorization.Story -> null
    is MultiRecipientSendAuthorization.GroupSend -> token.serialize()
  }

/**
 * Successful response for [UnauthMessagesService.sendMultiRecipientMessage].
 *
 * When sending using [MultiRecipientSendAuthorization.GroupSend], the server will report which
 * recipients are currently unregistered. For [MultiRecipientSendAuthorization.Story] the list will
 * always be empty.
 */
public class MultiRecipientMessageResponse(
  public val unregisteredIds: List<ServiceId>,
) {
  internal constructor(
    rawUnregisteredIds: Array<ByteArray>,
  ) : this(rawUnregisteredIds.map(ServiceId::parseFromFixedWidthBinary)) {}
}

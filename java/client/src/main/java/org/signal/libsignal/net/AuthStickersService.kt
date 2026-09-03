//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

/** The output of [AuthStickersService.getStickerUploadForms]. */
public data class GetStickerUploadFormsResponse(
  /** A randomly-generated ID for the new sticker pack. */
  val packId: String,
  /** An upload form clients must use to upload a manifest for the sticker pack. */
  val manifestUploadForm: S3UploadForm,
  /** Upload forms for individual stickers within the sticker pack. */
  val stickerUploadForms: List<S3UploadForm>,
)

public class AuthStickersService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Retrieve a set of upload forms that can be used to upload a sticker pack.
   *
   * A successful response is guaranteed to have the requested number of sticker upload forms.
   *
   * @param numberOfStickers Must be between 1 and 201 (inclusive).
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun getStickerUploadForms(
    numberOfStickers: Int,
  ): CompletableFuture<RequestResult<GetStickerUploadFormsResponse, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_get_sticker_upload_forms(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          numberOfStickers = numberOfStickers,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

public class AuthProfilesService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Returns a form to upload a legacy (v1) avatar.
   */
  public fun getAvatarUploadFormLegacy(
    aci: org.signal.libsignal.protocol.ServiceId.Aci,
    profileKey: org.signal.libsignal.zkgroup.profiles.ProfileKey,
  ): CompletableFuture<RequestResult<S3UploadForm, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_get_avatar_upload_form_legacy(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          aci = aci,
          profileKey = profileKey,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

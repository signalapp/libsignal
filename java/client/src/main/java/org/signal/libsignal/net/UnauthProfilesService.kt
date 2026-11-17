//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.liftExceptions
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.signal.libsignal.zkgroup.avatars.AvatarUploadCredentialPresentation
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredential
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequestContext
import java.io.IOException

/** Either [`RequestUnauthorizedException`] or [`ProfileNotFoundException`] */
public sealed interface GetProfileKeyCredentialFailure : BadRequestError

/**
 * The account's profile or profile version was not found, possibly because the account is not on
 * Signal.
 *
 * See the specific request docs for more information.
 */
public class ProfileNotFoundException :
  IOException,
  GetProfileKeyCredentialFailure {
  @CalledFromNative
  public constructor(message: String) : super(message) {
  }
}

public class UnauthProfilesService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Does an account with the given ACI or PNI exist?
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun accountExists(account: ServiceId): CompletableFuture<RequestResult<Boolean, Nothing>> =
    liftExceptions {
      NativeNice
        .UnauthenticatedChatConnection_account_exists(
          asyncCtx = this.connection.tokioAsyncContext,
          chat = this.connection,
          account = account,
        )
    }.mapWithCancellation(
      onSuccess = { RequestResult.Success(it) },
      onError = { err -> err.toRequestResult() },
    )

  /**
   * Fetches a profile key credential using the given request context.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means the profile key does
   * not match the access key stored on the server. A [ProfileNotFoundException] means the account
   * in question does not exist or does not have a profile (possible if they have not finished
   * setting up their account). Check [accountExists] if you need to distinguish between these
   * possibilities.
   */
  public fun getProfileKeyCredential(
    requestContext: ProfileKeyCredentialRequestContext,
    serverParams: ServerPublicParams,
  ): CompletableFuture<RequestResult<ExpiringProfileKeyCredential, GetProfileKeyCredentialFailure>> =
    liftExceptions {
      NativeNice
        .UnauthenticatedChatConnection_get_profile_key_credential(
          asyncCtx = this.connection.tokioAsyncContext,
          chat = this.connection,
          profileKeyRequestContext = requestContext,
          serverParams = serverParams,
        )
    }.mapWithCancellation(
      onSuccess = { RequestResult.Success(it) },
      onError = { err -> err.toRequestResult<GetProfileKeyCredentialFailure>() },
    )

  /**
   * Extend the TTL of a v2 avatar
   *
   * The server doesn’t know which v2 avatars correspond to which Signal account. As a result,
   * v2 avatars expire after a time. To keep an account’s avatar from expiring, clients must
   * call extendAvatarTtl() on a regular basis (recommended: every 90 days).
   *
   * It is safe to keep calling this during the v1->v2 transition. v1 avatars will just be
   * treated as "not found."
   *
   * @return either the CdnUrl of the current v2 avatar, or null, if none is set.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. An [InvalidAvatarUploadCredentialPresentationException]
   * will be thrown if the credential presentation is invalid.
   */
  public fun extendAvatarTtl(
    credential: org.signal.libsignal.zkgroup.avatars.AvatarUploadCredentialPresentation,
  ): CompletableFuture<RequestResult<CdnUrl?, InvalidAvatarUploadCredentialPresentationException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_extend_avatar_ttl(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = credential,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult<InvalidAvatarUploadCredentialPresentationException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Delete the account’s avatar from the CDN.
   *
   * Clients must also call setProfile() to remove the avatar URL from the profile data.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. An [InvalidAvatarUploadCredentialPresentationException]
   * will be thrown if the credential presentation is invalid.
   */
  public fun deleteAvatar(
    credential: org.signal.libsignal.zkgroup.avatars.AvatarUploadCredentialPresentation,
  ): CompletableFuture<RequestResult<Unit, InvalidAvatarUploadCredentialPresentationException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_delete_avatar(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = credential,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err ->
            err.toRequestResult<InvalidAvatarUploadCredentialPresentationException>()
          },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Returns a credential to upload a v2 avatar.
   *
   * After uploading the avatar, the client
   * must call setProfile() with the new avatar URL in the encrypted data.
   *
   * Because avatars are uploaded anonymously, they have an expiration equal to the
   * idle account expiration. Clients must periodically (recommended: every 90 days)
   * call [extendAvatarTtl] to extend the TTL.
   *
   * NOTE: any existing avatar associated with this credential will be deleted immediately
   * Clients should not be uploading v2 avatars until after the v1->v2 avatar transition.
   *
   * @param uploadLength Uploads will be limited to uploadLength bytes. It must be in the range [1, 10485760] (10 MiB),
   * else the server will reject the upload.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. An [InvalidAvatarUploadCredentialPresentationException]
   * will be thrown if the credential presentation is invalid.
   */
  public fun getAvatarUploadForm(
    credential: AvatarUploadCredentialPresentation,
    uploadLength: Int,
  ): CompletableFuture<RequestResult<S3UploadForm, InvalidAvatarUploadCredentialPresentationException>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_get_avatar_upload_form(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          credential = credential,
          uploadLength = uploadLength,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err ->
            err.toRequestResult<InvalidAvatarUploadCredentialPresentationException>()
          },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

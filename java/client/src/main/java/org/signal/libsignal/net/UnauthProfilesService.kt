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
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredential
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequestContext
import java.io.IOException

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
}

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

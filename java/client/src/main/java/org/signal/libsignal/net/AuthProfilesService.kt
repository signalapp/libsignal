//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.zkgroup.GenericServerPublicParams
import org.signal.libsignal.zkgroup.ZkCredentialKeyPair
import org.signal.libsignal.zkgroup.avatars.AvatarUploadCredential
import java.time.Instant

public class AuthProfilesService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Returns a form to upload a legacy (v1) avatar.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
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

  /**
   * Returns an anonymous credential that may be presented with avatar operations in
   * UnauthProfilesService.
   *
   * @param aci the ACI of the current account
   * @param keyPair the [ZkCredentialKeyPair] of the current account
   * @param rotationId the [ZkCredentialRotationId] returned by the last call to
   * [AuthAccountsService.setZkCredentialKey]
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [AccountMissingZkCredentialKeyException] will be thrown if
   * the account doesn't have a [org.signal.libsignal.zkgroup.ZkCredentialPublicKey] set (via
   * [AuthAccountsService.setZkCredentialKey]).
   */
  public fun getAvatarCredential(
    aci: ServiceId.Aci,
    keyPair: ZkCredentialKeyPair,
    rotationId: ZkCredentialRotationId,
    serverPublicParams: GenericServerPublicParams,
    currentTimeSeconds: Instant = Instant.now(),
    rng: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<AvatarUploadCredential, AccountMissingZkCredentialKeyException>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_get_avatar_credential(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          aci = aci,
          keyPair = keyPair,
          rotationId = rotationId,
          serverPublicParams = serverPublicParams,
          currentTimeSeconds = currentTimeSeconds.epochSecond,
          rng = rng,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult<AccountMissingZkCredentialKeyException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

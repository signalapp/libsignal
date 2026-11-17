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
import org.signal.libsignal.zkgroup.GenericServerPublicParams
import org.signal.libsignal.zkgroup.ZkCredentialKeyPair
import org.signal.libsignal.zkgroup.avatars.AvatarUploadCredential
import org.signal.libsignal.zkgroup.profiles.ProfileKey
import org.signal.libsignal.zkgroup.profiles.ProfileKeyVersion
import java.io.IOException
import java.time.Instant

public sealed class ProfileFieldWithMaxLength(
  public val maxLength: Int,
) {
  public data object GivenName : ProfileFieldWithMaxLength(128)

  public data object FamilyName : ProfileFieldWithMaxLength(128)

  public data object About : ProfileFieldWithMaxLength(512)

  public data object AboutEmoji : ProfileFieldWithMaxLength(32)

  public data object Avatar : ProfileFieldWithMaxLength(128)

  public data object PaymentAddress : ProfileFieldWithMaxLength(550)
}

public sealed class ProfileValidationError {
  /**
   * The profile field (byte) length exceeded the maximum
   */
  public data class FieldTooLong(
    public val field: ProfileFieldWithMaxLength,
    public val len: Int,
    public val maxLen: Int,
  ) : ProfileValidationError()

  /**
   * The profile's "given name" field cannot be empty
   */
  public data object GivenNameEmpty : ProfileValidationError()
}

public sealed interface SetProfileException : BadRequestError {
  /**
   * The provided profile was invalid
   */
  public class InvalidProfile :
    IOException,
    SetProfileException {
    public val profileValidationError: ProfileValidationError

    @CalledFromNative
    public constructor(profileValidationError: ProfileValidationError, message: String) : super(message) {
      this.profileValidationError = profileValidationError
    }
  }

  /**
   * The current data hash did not match the request's expectation, indicating
   * another device on the account may have written an update the caller does not know about.
   */
  public class ExpectedDataWriteConflict :
    IOException,
    SetProfileException {
    @CalledFromNative
    public constructor(message: String) : super(message) {
    }
  }

  /**
   * The current version did not match the request's expectation, indicating
   * another device on the account may have created a new version the caller does not know about.
   *
   * @property currentProfileVersion In certain, highly unlikely, cases, a new profile version might not be
   * distributed among all devices. These devices wouldn't be able to decrypt the
   * profile, but the value can be used to set a new version.
   */
  public class ExpectedVersionWriteConflict :
    IOException,
    SetProfileException {
    public val currentProfileVersion: ProfileKeyVersion?

    @CalledFromNative
    public constructor(currentProfileVersion: ProfileKeyVersion?, message: String) : super(message) {
      this.currentProfileVersion = currentProfileVersion
    }
  }

  /*
   * Payments are not permitted in the account's region, based on its phone
   * number or the caller's IP address if the account does not have a phone
   * number. The request should be retried without paymentAddress.
   */
  public class PaymentsForbiddenInRegion :
    IOException,
    SetProfileException {
    @CalledFromNative
    public constructor(message: String) : super(message) {
    }
  }
}

public sealed interface AuthGetProfileError : BadRequestError

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

  /**
   * Set the profile for the current account.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. This method can also result in a [SetProfileException].
   * See the docs on its subclasses for more details.
   *
   * @param aci the ACI of the current account
   * @param profileKey the profile key to use when setting the profile. This can be the same, or
   * different from the current profile key.
   *
   * @param expectedCurrentDataHash must exactly match the server’s view of the current profile v2
   * data hash. When changing to a new profile key, expectedCurrentDataHash must be null.
   * If this is the first v2 profile for this profile key, then expectedCurrentDataHash
   * must be null. Otherwise, expectedCurrentDataHash must be the result of the last
   * successful setProfile() invocation from across all devices on the account.
   *
   * Note that if an older client (not yet using libsignal to set profiles) sets a v1 profile,
   * this will clear out the v2 profile, and expectedCurrentDataHash should be null in
   * these cases.
   *
   * The easiest way to obtain the correct expectedCurrentDataHash is to invoke
   * getProfile() on the current account. The resulting FetchedProfile’s v2DataHash
   * will be the correct value (regardless of whether it’s null or not) to pass to the
   * expectedCurrentDataHash argument of this function.
   *
   * @param expectedCurrentProfileKeyVersion must be the current profile key version of the
   * account (or null if there is no current version). In case of mismatch, the resulting
   * error will contain the current profile key version, which may be passed into this parameter
   * on a subsequent request.
   *
   * @return The [ProfileDataHash] of the encrypted profile that was just uploaded.
   */
  public fun setProfile(
    aci: ServiceId.Aci,
    profileKey: ProfileKey,
    profile: Profile,
    expectedCurrentDataHash: ProfileDataHash?,
    expectedCurrentProfileKeyVersion: ProfileKeyVersion?,
    rng: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<ProfileDataHash, SetProfileException>> =
    liftExceptions {
      NativeNice
        .AuthenticatedChatConnection_set_profile(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          rng = rng,
          aci = aci,
          profileKey = profileKey,
          profile = profile,
          expectedCurrentDataHash = expectedCurrentDataHash,
          expectedCurrentProfileKeyVersion = expectedCurrentProfileKeyVersion,
        )
    }.mapWithCancellation(
      onSuccess = { RequestResult.Success(it) },
      onError = { err -> err.toRequestResult<SetProfileException>() },
    )

  /**
   * Retrieves profile data.
   *
   * Callers with an unidentified access key for the account should use the
   * unauth version instead.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. This method can also result in a [ProfileNotFoundException]
   * if the profile (version) cannot be found. A [ProfileCantBeDecodedException] will result if the
   * profile failed to decode (e.g. due to encryption or validation errors)
   *
   * @return null if the provided etag is up-to-date.
   */
  public fun getProfile(
    aci: ServiceId.Aci,
    profileKey: ProfileKey,
    etag: ProfileEtag?,
  ): CompletableFuture<RequestResult<FetchedProfile?, AuthGetProfileError>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_get_profile(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          aci = aci,
          profileKey = profileKey,
          etag = etag,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult<AuthGetProfileError>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

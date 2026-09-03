//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.BridgeConfirmedMfaKey
import org.signal.libsignal.internal.BridgeConfirmedMfaKeyMetadata
import org.signal.libsignal.internal.BridgeMfaKeyKind
import org.signal.libsignal.internal.BridgeMfaMetadata
import org.signal.libsignal.internal.BridgePendingTotpKey
import org.signal.libsignal.internal.BridgeTotpParameters
import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation
import java.time.Duration
import java.time.Instant

/**
 * The user-specified metadata attached to a multi-factor authentication (MFA) key, such as a TOTP
 * key, on the account.
 *
 * This is stored encrypted on the server, so only the account's own devices can read it.
 */
public data class MfaMetadata(
  /**
   * A human-readable name for the key, at most [NAME_MAX_LENGTH] bytes when encoded as UTF-8 and
   * not containing U+0000.
   */
  val name: String,
  /**
   * When the key was created.
   *
   * Stored with one-second granularity, so a value read back from the server may be truncated
   * relative to the value that was written. Must not be before the Unix epoch.
   */
  val createdAt: Instant,
) {
  public companion object {
    /**
     * The maximum length of [name], in UTF-8 bytes.
     */
    public const val NAME_MAX_LENGTH: Int = 98

    internal fun fromInternal(it: BridgeMfaMetadata): MfaMetadata =
      MfaMetadata(
        name = it.name,
        createdAt = it.createdAt,
      )
  }
}

/**
 * The parameters a TOTP generator needs, besides the key itself, to produce one-time passwords the
 * server will accept.
 */
public data class TotpParameters(
  /**
   * The HMAC algorithm (e.g. "HmacSHA256") used by the TOTP generator.
   */
  val algorithm: String,
  /**
   * The length of one-time passwords (in decimal digits) produced and expected by the TOTP
   * generator.
   */
  val passwordLength: Int,
  /**
   * The time step used by the TOTP generator.
   */
  val timeStep: Duration,
) {
  public companion object {
    internal fun fromInternal(it: BridgeTotpParameters): TotpParameters =
      TotpParameters(
        algorithm = it.algorithm,
        passwordLength = it.passwordLength,
        timeStep = Duration.ofSeconds(it.timeStepSeconds.toLong()),
      )
  }
}

/**
 * A newly-generated TOTP key that is not yet active.
 *
 * Returned by [AuthAccountsService.generateTotpKey]; the key only starts being accepted for the
 * account once it is confirmed via [AuthAccountsService.confirmTotpKey].
 */
public data class PendingTotpKey(
  /**
   * The raw TOTP key.
   */
  val key: ByteArray,
  /**
   * The TOTP parameters associated with the generated key.
   */
  val parameters: TotpParameters,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as PendingTotpKey

    if (!key.contentEquals(other.key)) return false
    if (parameters != other.parameters) return false

    return true
  }

  override fun hashCode(): Int {
    var result = key.contentHashCode()
    result = 31 * result + parameters.hashCode()
    return result
  }

  override fun toString(): String = "PendingTotpKey(key=<redacted>, parameters=$parameters)"

  public companion object {
    public fun fromInternal(it: BridgePendingTotpKey): PendingTotpKey =
      PendingTotpKey(
        key = it.key,
        parameters = TotpParameters.fromInternal(it.parameters),
      )
  }
}

/**
 * The kind of a confirmed MFA key.
 */
public enum class MfaKeyKind {
  /**
   * A TOTP key; see [AuthAccountsService.generateTotpKey].
   */
  TOTP,

  /**
   * A kind of key this version of libsignal doesn't know about; see
   * [AuthAccountsService.listMfaKeys].
   */
  UNKNOWN,
  ;

  internal companion object {
    internal fun fromInternal(it: BridgeMfaKeyKind): MfaKeyKind =
      when (it) {
        BridgeMfaKeyKind.Totp -> TOTP
        BridgeMfaKeyKind.Unknown -> UNKNOWN
      }
  }
}

/**
 * A confirmed multi-factor authentication (MFA) key on the account, as returned by
 * [AuthAccountsService.listMfaKeys].
 */
public data class ConfirmedMfaKey(
  /**
   * The account-specific identifier for this key.
   */
  val id: Int,
  /**
   * The user-specified name and creation time attached to this key, or `null` if it could not be
   * decrypted with the provided SVR key; see [AuthAccountsService.listMfaKeys].
   */
  val metadata: MfaMetadata?,
  /**
   * What kind of MFA key this is.
   */
  val kind: MfaKeyKind,
) {
  public companion object {
    public fun fromInternal(it: BridgeConfirmedMfaKey): ConfirmedMfaKey =
      ConfirmedMfaKey(
        id = it.id,
        metadata =
          when (val metadata = it.metadata) {
            is BridgeConfirmedMfaKeyMetadata.Metadata -> MfaMetadata.fromInternal(metadata._0)
            BridgeConfirmedMfaKeyMetadata.Unreadable -> null
          },
        kind = MfaKeyKind.fromInternal(it.kind),
      )
  }
}

/**
 * Errors that [AuthAccountsService.generateTotpKey] can produce, in addition to the generic
 * request errors.
 */
public sealed interface GenerateTotpKeyError : BadRequestError

/**
 * Errors that [AuthAccountsService.confirmTotpKey] can produce, in addition to the generic
 * request errors.
 */
public sealed interface ConfirmTotpKeyError : BadRequestError

public class AuthAccountsService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Deletes the authenticated account, purging all associated data in the process.
   *
   * Only the account's primary device may delete the account.
   *
   * Deleting the account also invalidates its connections, so the response can race the resulting
   * disconnect. If the connection is interrupted before a response arrives, the deletion may
   * nevertheless have taken effect; callers should not treat a transport error as proof the
   * account still exists.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun deleteAccount(): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_delete_account(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Sets the registration lock secret for the authenticated account, given the account's SVR key
   * (which Signal clients historically call the "master key").
   *
   * Internally, we derive the registration lock secret from the SVR key and send only that secret.
   * The SVR key itself never leaves the device.
   *
   * While the registration lock is set, re-registering the account's phone number requires proving
   * knowledge of the secret.
   *
   * Only the account's primary device may set a registration lock.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun setRegistrationLock(svrKey: SvrKey): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_registration_lock(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          svrKey = svrKey.internalContentsForJNI,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Removes any registration lock from the authenticated account.
   *
   * This also succeeds if the account has no registration lock set, so a caller retrying a removal
   * sees the same result as the original call.
   *
   * Only the account's primary device may clear a registration lock.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun clearRegistrationLock(): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_clear_registration_lock(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Sets the registration recovery password for the authenticated account, given the account's SVR
   * key (which Signal clients historically call the "master key").
   *
   * Internally, we derive the registration recovery password from the SVR key and send only that
   * derived password. The SVR key itself never leaves the device.
   *
   * The registration recovery password lets the account re-register its phone number without SMS
   * verification. Any of the account's devices may set it.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun setRegistrationRecoveryPassword(svrKey: SvrKey): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_registration_recovery_password(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          svrKey = svrKey.internalContentsForJNI,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Sets whether the authenticated account may be discovered by phone number via the Contact
   * Discovery Service (CDS).
   *
   * If `false`, other users must discover this account by other means (e.g. by username).
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun setDiscoverableByPhoneNumber(discoverable: Boolean): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_discoverable_by_phone_number(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          discoverable = discoverable,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Generates and stores a new pending TOTP key for the authenticated account.
   *
   * The key is generated by the server and returned along with the parameters a TOTP generator
   * needs to derive one-time passwords from it.
   *
   * The key does not become active until the client calls [confirmTotpKey] to prove it can
   * generate one-time passwords using the new key. The caller has 24 hours to confirm the key
   * after it has been generated. This is the only time the key material for this TOTP key is
   * available; if it is lost, a new one will need to be generated.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [TooManyTotpKeysException] indicates the account already
   * has too many TOTP keys, and a [TooManyMfaKeysException] that it has too many MFA keys of all
   * kinds; either way, one must be removed before adding more.
   */
  public fun generateTotpKey(): CompletableFuture<RequestResult<PendingTotpKey, GenerateTotpKeyError>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_generate_totp_key(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(PendingTotpKey.fromInternal(it)) },
          onError = { err -> err.toRequestResult<GenerateTotpKeyError>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Confirms the account's pending TOTP key (see [generateTotpKey]), thus activating it.
   *
   * A TOTP key must be confirmed within 24 hours of its generation.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [OneTimePasswordNotVerifiedException] indicates the
   * one-time password was not accepted for any reason. A [TooManyMfaKeysException] indicates
   * the account filled up with MFA keys between generating and confirming this one.
   *
   * A negative [oneTimePassword], a [metadata] name longer than
   * [MfaMetadata.NAME_MAX_LENGTH] bytes of UTF-8 or containing U+0000, or a metadata creation date
   * before the Unix epoch is a programmer error, reported as an [IllegalArgumentException] wrapped
   * in [RequestResult.ApplicationError].
   *
   * @param oneTimePassword A one-time password derived from the pending key. This should be
   * provided by the user from their TOTP app, proving they have stored the key and can correctly
   * generate passwords from it going forward.
   * @param metadata Metadata (name, creation time) to attach to the newly-confirmed key; stored
   * encrypted, so that it may not be read by the server
   * @param svrKey The account's SVR key
   * @return The account-specific identifier assigned to the newly-confirmed key
   */
  public fun confirmTotpKey(
    oneTimePassword: Int,
    metadata: MfaMetadata,
    svrKey: SvrKey,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<Int, ConfirmTotpKeyError>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_confirm_totp_key(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          oneTimePassword = oneTimePassword,
          name = metadata.name,
          createdAt = metadata.createdAt,
          svrKey = svrKey.internalContentsForJNI,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult<ConfirmTotpKeyError>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Lists the confirmed MFA keys for the authenticated account.
   *
   * An item with a `null` [ConfirmedMfaKey.metadata] indicates that the metadata attached to
   * that key could not be decrypted with the provided [SvrKey] (e.g. because the SVR key / AEP
   * has rotated since the key was stored). If the user recalls the name for the key, this state
   * is recoverable by calling [setMfaKeyMetadata]; otherwise, the key with the unreadable name
   * may be removed by calling [removeMfaKey].
   *
   * Similarly, a key of a kind this version of libsignal doesn't recognize is still listed, with
   * [MfaKeyKind.UNKNOWN] (e.g. because it was added from a linked device running a newer version
   * of Signal).
   *
   * Pending (unconfirmed) keys are not included, and the key material itself is never returned.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun listMfaKeys(svrKey: SvrKey): CompletableFuture<RequestResult<List<ConfirmedMfaKey>, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_list_mfa_keys(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          svrKey = svrKey.internalContentsForJNI,
        ).mapWithCancellation(
          onSuccess = { keys -> RequestResult.Success(keys.map { ConfirmedMfaKey.fromInternal(it) }) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Replaces the metadata attached to the confirmed MFA key identified by [keyId].
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [MfaKeyNotFoundException] indicates no confirmed MFA key
   * with the provided identifier was found on the account.
   *
   * A [keyId] outside the range of identifiers the server assigns, a [metadata] name longer than
   * [MfaMetadata.NAME_MAX_LENGTH] bytes of UTF-8 or containing U+0000, or a metadata creation date
   * before the Unix epoch is a programmer error, reported as an [IllegalArgumentException] wrapped
   * in [RequestResult.ApplicationError].
   */
  public fun setMfaKeyMetadata(
    keyId: Int,
    metadata: MfaMetadata,
    svrKey: SvrKey,
    rngSeedForTesting: DeterministicRandomSeedUseOnlyForTesting? = null,
  ): CompletableFuture<RequestResult<Unit, MfaKeyNotFoundException>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_set_mfa_key_metadata(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          keyId = keyId,
          name = metadata.name,
          createdAt = metadata.createdAt,
          svrKey = svrKey.internalContentsForJNI,
          rng = rngSeedForTesting,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult<MfaKeyNotFoundException>() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }

  /**
   * Removes the MFA key identified by [keyId] from the authenticated account.
   *
   * This is idempotent; removing a key ID that is not on the account also succeeds. A [keyId]
   * outside the range of identifiers the server assigns, however, is a programmer error, reported
   * as an [IllegalArgumentException] wrapped in [RequestResult.ApplicationError].
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun removeMfaKey(keyId: Int): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_remove_mfa_key(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          keyId = keyId,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

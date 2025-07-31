//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.internal.toResultFuture
import org.signal.libsignal.messagebackup.BackupForwardSecrecyToken
import org.signal.libsignal.messagebackup.BackupKey

/**
 * Service for Secure Value Recovery for Backups (SVR-B) operations.
 *
 * This service provides forward secrecy for Signal backups using SVR-B. Forward secrecy ensures
 * that even if the user's Account Entropy Pool or Backup Key is compromised, the attacker can
 * decrypt a very small number of past backups. This is achieved by storing a token
 * in a secure enclave inside the SVR-B server, which provably attests that it
 * only stores a single token at a time for each user.
 *
 * ## Overview
 *
 * To achieve these properties, a secret token is required to derive the actual encryption
 * keys for the backup. At backup time, this token must be stored in the SVR-B server, overwriting the
 * previous token. At restore time, the token must be retrieved from the SVR-B server, and used to
 * derive the encryption keys for the backup.
 *
 * ## Storage Flow
 *
 * 1. Create a [Network] instance and get the [SvrB] service via [Network.svrB]
 * 2. Call [SvrB.store]
 *    - Pass the `nextBackupSecretData` from the last **successful** [SvrB.store] or [SvrB.restore] call
 *    - If no previous backup exists or the secret data is unavailable, pass `null`
 * 3. Use the returned forward secrecy token to derive encryption keys
 * 4. Encrypt and upload the backup data to the user's remote, off-device storage location, including the
 *    returned [SvrBStoreResponse.metadata]. The upload **must succeed**
 *    before proceeding or the previous backup might become unretrievable.
 * 5. Store the [SvrBStoreResponse.nextBackupSecretData] locally, overwriting any previously-saved value.
 *
 * ## Secret handling
 *
 * When calling [SvrB.store], the `previousSecretData` parameter
 * must be from the last call to [SvrB.store] or [SvrB.restore] that
 * succeeded. The returned secret from a successful `store()` or `restore()` call should
 * be persisted until it is overwritten by the value from a subsequent
 * successful call. The caller should pass `null` as `previousSecretData`
 * only for the very first backup from a device.
 *
 * ## Restore Flow
 *
 * 1. Create a [Network] instance and get the [SvrB] service via [Network.svrB]
 * 2. Fetch the backup metadata from storage
 * 3. Call [SvrB.restore] to get the forward secrecy token
 * 4. Use the token to derive decryption keys
 * 5. Decrypt and restore the backup data
 * 6. Store the [SvrBRestoreResponse.nextBackupSecretData] locally.
 *
 * ## Usage
 * ```kotlin
 * val net = Network(Network.Environment.PRODUCTION, "Signal Android")
 * val auth = Network.Auth(username = "myUsername", password = "myPassword")
 * val svrB = net.svrB(auth)
 *
 * // Prepare a backup
 * val stored = svrB.store(myKey, previousSecretData).get().getOrThrow()
 * // ... store backup with stored.forwardSecrecyToken remotely ...
 * // Securely persist stored.nextBackupSecretData for the next backup
 * ```
 *
 * @see [BackupKey], [MessageBackupKey], [BackupForwardSecrecyToken]
 */
public class SvrB internal constructor(
  private val network: Network,
  private val username: String,
  private val password: String,
) {

  /**
   * Prepares a backup for storage with forward secrecy guarantees.
   *
   * This makes a network call to the SVR-B server to store the forward secrecy token
   * and returns a [SvrBStoreResponse]. See its fields' documentation and [SvrB]
   * for how to continue persisting the backup on success.
   *
   * @param backupKey The backup key derived from the Account Entropy Pool (AEP).
   * @param previousSecretData Optional secret data from the most recent previous backup.
   * **Critical**: This MUST be the secret data from the last [store] or [restore]
   * whose returned `metadata` was successfully uploaded, and whose `nextBackupSecretData` was persisted.
   * If `null`, starts a new chain and renders any prior backups unretrievable; this should
   * only be used for the very first backup from a device.
   * @return a [CompletableFuture] that completes with:
   *   - [Result.success] containing [SvrBStoreResponse] with the forward secrecy token, metadata, and secret data on success
   *   - [Result.failure] containing [SvrException] if the previous secret data is malformed, or for encryption/decryption errors
   *   - [Result.failure] containing [NetworkException] if the network operation fails (connection, service, or timeout errors)
   *   - [Result.failure] containing [NetworkProtocolException] if there is a protocol error
   *   - [Result.failure] containing [AttestationFailedException] if enclave attestation fails
   *   - [Result.failure] containing [SvrException] for other SVR request failures
   */
  public fun store(
    backupKey: BackupKey,
    previousSecretData: ByteArray?,
  ): CompletableFuture<Result<SvrBStoreResponse>> {
    val nativeFuture = network.asyncContext.guardedMap { asyncContextHandle ->
      network.connectionManager.guardedMap { connectionManagerHandle ->
        Native.SecureValueRecoveryForBackups_StoreBackup(
          asyncContextHandle,
          backupKey.internalContentsForJNI,
          previousSecretData ?: byteArrayOf(),
          connectionManagerHandle,
          username,
          password,
        )
      }
    }

    return nativeFuture.thenApply { backupResponseHandle ->
      val response = BackupStoreResponse(backupResponseHandle)
      response.guardedMap { _ ->
        SvrBStoreResponse(
          forwardSecrecyToken = BackupForwardSecrecyToken(
            response.guardedMapChecked(Native::BackupStoreResponse_GetForwardSecrecyToken),
          ),
          nextBackupSecretData = response.guardedMapChecked(Native::BackupStoreResponse_GetNextBackupSecretData),
          metadata = response.guardedMapChecked(Native::BackupStoreResponse_GetOpaqueMetadata),
        )
      }
    }.toResultFuture()
  }

  /**
   * Fetches the forward secrecy token needed to decrypt a backup.
   *
   * This function makes a network call to the SVR-B server to retrieve the forward secrecy token
   * associated with a specific backup. The token is required to derive the message backup keys
   * for decryption.
   *
   * The typical restore flow:
   * 1. Fetch the backup metadata (stored in a header in the backup file)
   * 2. Call this function to retrieve the forward secrecy token from SVR-B
   * 3. Use the token to derive message backup keys
   * 4. Decrypt and restore the backup data
   * 5. Store the returned [SvrBRestoreResponse.nextBackupSecretData] locally.
   *
   * @param backupKey The backup key derived from the Account Entropy Pool (AEP).
   * @param metadata The metadata that was stored in a header in the backup file during backup creation.
   * @return a [CompletableFuture] that completes with:
   *   - [Result.success] containing [BackupForwardSecrecyToken] needed to derive keys for decrypting the backup
   *   - [Result.failure] containing [SvrException] if the metadata is invalid
   *   - [Result.failure] containing [RestoreFailedException] if restoration fails (with remaining tries count)
   *   - [Result.failure] containing [DataMissingException] if the backup data is not found on the server
   *   - [Result.failure] containing [NetworkException] if the network operation fails (connection, service, or timeout errors)
   *   - [Result.failure] containing [NetworkProtocolException] if there is a protocol error
   *   - [Result.failure] containing [AttestationFailedException] if enclave attestation fails
   *   - [Result.failure] containing [SvrException] for other SVR request failures
   */
  public fun restore(
    backupKey: BackupKey,
    metadata: ByteArray,
  ): CompletableFuture<Result<SvrBRestoreResponse>> {
    val nativeFuture = network.asyncContext.guardedMap { asyncContextHandle ->
      network.connectionManager.guardedMap { connectionManagerHandle ->
        Native.SecureValueRecoveryForBackups_RestoreBackupFromServer(
          asyncContextHandle,
          backupKey.internalContentsForJNI,
          metadata,
          connectionManagerHandle,
          username,
          password,
        )
      }
    }

    return nativeFuture.thenApply { backupResponseHandle ->
      val response = BackupRestoreResponse(backupResponseHandle)
      response.guardedMap { _ ->
        SvrBRestoreResponse(
          forwardSecrecyToken = BackupForwardSecrecyToken(
            response.guardedMapChecked(Native::BackupRestoreResponse_GetForwardSecrecyToken),
          ),
          nextBackupSecretData = response.guardedMapChecked(Native::BackupRestoreResponse_GetNextBackupSecretData),
        )
      }
    }.toResultFuture()
  }
}

/**
 * Native handle wrapper for backup response from the store operation.
 */
private class BackupStoreResponse internal constructor(
  nativeHandle: Long,
) : NativeHandleGuard.SimpleOwner(nativeHandle) {
  override fun release(nativeHandle: Long) {
    Native.BackupStoreResponse_Destroy(nativeHandle)
  }
}

/**
 * Native handle wrapper for backup response from the restore operation.
 */
private class BackupRestoreResponse internal constructor(
  nativeHandle: Long,
) : NativeHandleGuard.SimpleOwner(nativeHandle) {
  override fun release(nativeHandle: Long) {
    Native.BackupRestoreResponse_Destroy(nativeHandle)
  }
}

/**
 * The result of preparing a backup to be stored with forward secrecy guarantees.
 *
 * This context contains all the necessary components to encrypt and store a backup using a
 * key derived from both the user's Account Entropy Pool and the SVR-B-protected
 * Forward Secrecy Token.
 *
 * @see [BackupForwardSecrecyToken]
 */
public data class SvrBStoreResponse(
  /**
   * The forward secrecy token used to derive [MessageBackupKey] instances.
   *
   * This token provides forward secrecy guarantees by ensuring that compromise of the backup key
   * alone is insufficient to decrypt backups. Each backup is protected by a value stored on
   * the SVR-B server that must be retrieved during restoration.
   */
  public val forwardSecrecyToken: BackupForwardSecrecyToken,

  /**
   * Opaque value that must be persisted and provided to the next call to [SvrB.store].
   *
   * See the [SvrB] documentation for lifecycle and persistence handling
   * for this value.
   */
  public val nextBackupSecretData: ByteArray,

  /**
   * Opaque metadata that must be stored in the backup file.
   *
   * This metadata contains the encrypted forward secrecy token and other information required
   * to restore the backup. It must be retrievable when restoring the backup, as it's required
   * to fetch the forward secrecy token from SVR-B. This is currently stored in the header of
   * the backup file.
   */
  public val metadata: ByteArray,
)

/**
 * The result of restoring a backup.
 *
 * This context contains all the necessary components to decrypt a backup using a
 * key derived from both the user's Account Entropy Pool and the SVR-B-protected
 * Forward Secrecy Token.
 *
 * @see [BackupForwardSecrecyToken]
 */
public data class SvrBRestoreResponse(
  /**
   * The forward secrecy token used to derive [MessageBackupKey] instances.
   *
   * This token provides forward secrecy guarantees by ensuring that compromise of the backup key
   * alone is insufficient to decrypt backups. Each backup is protected by a value stored on
   * the SVR-B server that must be retrieved during restoration.
   */
  public val forwardSecrecyToken: BackupForwardSecrecyToken,

  /**
   * Opaque value that must be persisted and provided to the next call to [SvrB.store].
   *
   * See the [SvrB] documentation for lifecycle and persistence handling
   * for this value.
   */
  public val nextBackupSecretData: ByteArray,
)

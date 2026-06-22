//
// Copyright (C) 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

@file:Suppress(
  "ktlint:standard:function-naming",
  "ktlint:standard:property-naming",
  "ktlint:standard:filename",
  "ktlint:standard:max-line-length",
)

package org.signal.libsignal.internal

import org.signal.libsignal.internal.NativeNiceHelpers.identity
import org.signal.libsignal.internal.NativeNiceHelpers.mapPair

internal object NativeNice {
  public fun AuthenticatedChatConnection_set_device_name(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.AuthenticatedChatConnection,
    deviceId: Int,
    encryptedName: ByteArray,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_device_id = identity(deviceId)
    val ffi_encrypted_name = identity(encryptedName)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.AuthenticatedChatConnection_set_device_name(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_device_id,
          ffi_encrypted_name,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun UnauthenticatedChatConnection_account_exists(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    account: org.signal.libsignal.protocol.ServiceId,
  ): CompletableFuture<Boolean> {
    val ffi_chat = identity(chat)
    val ffi_account = (org.signal.libsignal.protocol.ServiceId::toServiceIdFixedWidthBinary)(account)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_account_exists(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_account,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun UnauthenticatedChatConnection_backup_delete_all(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_delete_all(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun UnauthenticatedChatConnection_backup_get_cdn_credentials(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    cdn: Int,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<org.signal.libsignal.net.BackupCdnCredentials> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_cdn = identity(cdn)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_get_cdn_credentials(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_cdn,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply {
        org.signal.libsignal.net.BackupCdnCredentials
          .fromFfiHeaders(it)
      }
  }

  public fun UnauthenticatedChatConnection_backup_get_svrb_credentials(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<Pair<String, String>> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_get_svrb_credentials(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
      .thenApply { mapPair<String, String, String, String>({ identity(it) }, { identity(it) })(it) }
  }

  public fun UnauthenticatedChatConnection_backup_refresh(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_refresh(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }

  public fun UnauthenticatedChatConnection_backup_set_public_key(
    asyncCtx: TokioAsyncContext,
    chat: org.signal.libsignal.net.UnauthenticatedChatConnection,
    credential: org.signal.libsignal.zkgroup.backups.BackupAuthCredential,
    serverKeys: org.signal.libsignal.zkgroup.GenericServerPublicParams,
    signingKey: org.signal.libsignal.protocol.ecc.ECPrivateKey,
    rng: org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting?,
  ): CompletableFuture<Void?> {
    val ffi_chat = identity(chat)
    val ffi_credential =
      (org.signal.libsignal.zkgroup.backups.BackupAuthCredential::getInternalContentsForJNI)(credential)
    val ffi_server_keys =
      (org.signal.libsignal.zkgroup.GenericServerPublicParams::getInternalContentsForJNI)(serverKeys)
    val ffi_signing_key = identity(signingKey)
    val ffi_rng =
      org.signal.libsignal.net.DeterministicRandomSeedUseOnlyForTesting
        .toFfi(rng)
    val ffiOut =
      NativeHandleGuard(asyncCtx).use { asyncCtxHandle ->
        Native.UnauthenticatedChatConnection_backup_set_public_key(
          asyncCtxHandle.nativeHandle(),
          ffi_chat,
          ffi_credential,
          ffi_server_keys,
          ffi_signing_key,
          ffi_rng,
        )
      }
    return ffiOut
      .makeCancelable(asyncCtx)
  }
}

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.mapWithCancellation
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.zkgroup.groupsend.GroupSendFullToken

public sealed class UserBasedAuthorization {
  public data class AccessKey(
    val bytes: ByteArray,
  ) : UserBasedAuthorization() {
    // Because the default equals+hashCode compare based on identity, not value
    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (javaClass != other?.javaClass) return false

      other as AccessKey

      if (!bytes.contentEquals(other.bytes)) return false

      return true
    }

    override fun hashCode(): Int = bytes.contentHashCode()
  }

  public data class GroupSend(
    val token: GroupSendFullToken,
  ) : UserBasedAuthorization()

  public object UnrestrictedUnauthenticatedAccess : UserBasedAuthorization()
}

public sealed class DeviceSpecifier {
  public object AllDevices : DeviceSpecifier()

  public data class SpecificDevice(
    val deviceId: Int,
  ) : DeviceSpecifier()
}

public sealed interface GetPreKeysError : BadRequestError

public class UnauthKeysService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Fetch the prekeys for a given target user
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError]. A [RequestUnauthorizedException] means `auth` is not valid
   * for the target. A [ServiceIdNotFoundException] means that the requested identity or device does
   * not exist or device has no available prekeys.
   */
  public fun getPreKeys(
    target: ServiceId,
    device: DeviceSpecifier,
    auth: UserBasedAuthorization,
  ): CompletableFuture<RequestResult<Pair<IdentityKey, List<PreKeyBundle>>, GetPreKeysError>> {
    val device =
      when (device) {
        is DeviceSpecifier.SpecificDevice -> {
          require(device.deviceId >= 0)
          device.deviceId
        }

        is DeviceSpecifier.AllDevices -> -1
      }
    return try {
      connection.runWithContextAndConnectionHandles { asyncCtx, conn ->
        // Suppress the warnings about java.lang.Object being inferred as the type
        // parameter for mapWithCancellation
        @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
        when (auth) {
          is UserBasedAuthorization.AccessKey -> {
            Native.UnauthenticatedChatConnection_get_pre_keys_access_key_auth(
              asyncCtx,
              conn,
              auth.bytes,
              target.toServiceIdFixedWidthBinary(),
              device,
            )
          }

          is UserBasedAuthorization.GroupSend -> {
            Native.UnauthenticatedChatConnection_get_pre_keys_group_auth(
              asyncCtx,
              conn,
              auth.token.serialize(),
              target.toServiceIdFixedWidthBinary(),
              device,
            )
          }

          is UserBasedAuthorization.UnrestrictedUnauthenticatedAccess -> {
            Native.UnauthenticatedChatConnection_get_pre_keys_unrestricted_auth(
              asyncCtx,
              conn,
              target.toServiceIdFixedWidthBinary(),
              device,
            )
          }
        }.mapWithCancellation(
          onSuccess = { out: Any ->
            val (publicKey, preKeyBundles) = out as Pair<*, *>
            @Suppress("UNCHECKED_CAST") // The cast _is_ checked because Arrays don't use type erasure
            RequestResult.Success(
              Pair(
                IdentityKey(publicKey as ECPublicKey),
                (preKeyBundles as Array<PreKeyBundle>).toList(),
              ),
            )
          },
          onError = { err -> err.toRequestResult<GetPreKeysError>() },
        )
      }
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
  }
}

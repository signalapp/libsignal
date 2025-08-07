//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMPublicKey

/**
 * A class that contains a remote PreKey and collection of associated items.
 *
 * @author Moxie Marlinspike
 */
public class PreKeyBundle(
  registrationId: Int,
  deviceId: Int,
  preKeyId: Int,
  preKeyPublic: ECPublicKey?,
  signedPreKeyId: Int,
  signedPreKeyPublic: ECPublicKey,
  signedPreKeySignature: ByteArray,
  identityKey: IdentityKey,
  kyberPreKeyId: Int,
  kyberPreKeyPublic: KEMPublicKey,
  kyberPreKeySignature: ByteArray,
) : NativeHandleGuard.SimpleOwner(
    createNativeFrom(
      registrationId,
      deviceId,
      preKeyId,
      preKeyPublic,
      signedPreKeyId,
      signedPreKeyPublic,
      signedPreKeySignature,
      identityKey,
      kyberPreKeyId,
      kyberPreKeyPublic,
      kyberPreKeySignature,
    ),
  ) {
  public companion object {
    // -1 is treated as Option<u32>::None by the bridging layer
    public const val NULL_PRE_KEY_ID: Int = -1
  }

  protected override fun release(nativeHandle: Long) {
    Native.PreKeyBundle_Destroy(nativeHandle)
  }

  /**
   * @return the device ID this PreKey belongs to.
   */
  public val deviceId: Int
    get() = guardedMapChecked(Native::PreKeyBundle_GetDeviceId)

  /**
   * @return the unique pre key ID or -1 if the bundle has none.
   */
  public val preKeyId: Int
    get() = guardedMapChecked(Native::PreKeyBundle_GetPreKeyId)

  public val preKey: ECPublicKey?
    get() =
      guardedMapChecked(Native::PreKeyBundle_GetPreKeyPublic).let {
        if (it == 0L) return null
        ECPublicKey(it)
      }

  /**
   * @return the unique key ID for this signed prekey.
   */
  public val signedPreKeyId: Int
    get() = guardedMapChecked(Native::PreKeyBundle_GetSignedPreKeyId)

  /**
   * @return the signed prekey for this PreKeyBundle.
   */
  public val signedPreKey: ECPublicKey
    get() = ECPublicKey(guardedMapChecked(Native::PreKeyBundle_GetSignedPreKeyPublic))

  /**
   * @return the signature over the signed prekey.
   */
  public val signedPreKeySignature: ByteArray
    get() = guardedMapChecked(Native::PreKeyBundle_GetSignedPreKeySignature)

  /**
   * @return the [IdentityKey] of this PreKey's owner.
   */
  public val identityKey: IdentityKey
    get() =
      IdentityKey(
        ECPublicKey(
          guardedMapChecked(Native::PreKeyBundle_GetIdentityKey),
        ),
      )

  /**
   * @return the registration ID associated with this PreKey.
   */
  public val registrationId: Int
    get() = guardedMapChecked(Native::PreKeyBundle_GetRegistrationId)

  /**
   * @return the unique key ID for the Kyber prekey.
   */
  public val kyberPreKeyId: Int
    get() = guardedMapChecked(Native::PreKeyBundle_GetKyberPreKeyId)

  /**
   * @return the public key for this Kyber prekey.
   */
  public val kyberPreKey: KEMPublicKey
    get() = KEMPublicKey(guardedMapChecked(Native::PreKeyBundle_GetKyberPreKeyPublic))

  /**
   * @return the signature over the kyber prekey.
   */
  public val kyberPreKeySignature: ByteArray
    get() = guardedMapChecked(Native::PreKeyBundle_GetKyberPreKeySignature)
}

private fun createNativeFrom(
  registrationId: Int,
  deviceId: Int,
  preKeyId: Int,
  preKeyPublic: ECPublicKey?,
  signedPreKeyId: Int,
  signedPreKeyPublic: ECPublicKey,
  signedPreKeySignature: ByteArray,
  identityKey: IdentityKey,
  kyberPreKeyId: Int,
  kyberPreKeyPublic: KEMPublicKey,
  kyberPreKeySignature: ByteArray,
): Long =
  NativeHandleGuard(preKeyPublic).use { preKeyPublicGuard ->
    signedPreKeyPublic.guardedMap { signedPreKeyPublicHandle ->
      identityKey.getPublicKey().guardedMap { identityKeyHandle ->
        kyberPreKeyPublic.guardedMap { kyberPreKeyPublicHandle ->
          Native.PreKeyBundle_New(
            registrationId,
            deviceId,
            preKeyId,
            preKeyPublicGuard.nativeHandle(),
            signedPreKeyId,
            signedPreKeyPublicHandle,
            signedPreKeySignature,
            identityKeyHandle,
            kyberPreKeyId,
            kyberPreKeyPublicHandle,
            kyberPreKeySignature,
          )
        }
      }
    }
  }

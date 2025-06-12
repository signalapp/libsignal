//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

@file:JvmName("Curve")

package org.signal.libsignal.protocol.ecc

import org.signal.libsignal.protocol.InvalidKeyException

class Curve {
  companion object {
    const val DJB_TYPE = 0x05

    @JvmStatic
    fun generateKeyPair(): ECKeyPair {
      val privateKey = ECPrivateKey.generate()
      val publicKey = privateKey.publicKey()
      return ECKeyPair(publicKey, privateKey)
    }

    @JvmStatic
    @Throws(InvalidKeyException::class)
    fun decodePoint(bytes: ByteArray?, offset: Int): ECPublicKey {
      if (bytes == null || bytes.size - offset < 1) {
        throw InvalidKeyException("No key type identifier")
      }

      return ECPublicKey(bytes, offset)
    }

    @JvmStatic
    @Throws(InvalidKeyException::class)
    fun decodePrivatePoint(bytes: ByteArray?): ECPrivateKey {
      return ECPrivateKey(bytes)
    }

    @JvmStatic
    @Throws(InvalidKeyException::class)
    fun calculateAgreement(publicKey: ECPublicKey?, privateKey: ECPrivateKey?): ByteArray {
      if (publicKey == null) {
        throw InvalidKeyException("public value is null")
      }

      if (privateKey == null) {
        throw InvalidKeyException("private value is null")
      }

      return privateKey.calculateAgreement(publicKey)
    }

    @JvmStatic
    @Throws(InvalidKeyException::class)
    fun verifySignature(signingKey: ECPublicKey?, message: ByteArray?, signature: ByteArray?): Boolean {
      if (signingKey == null || message == null || signature == null) {
        throw InvalidKeyException("Values must not be null")
      }

      return signingKey.verifySignature(message, signature)
    }

    @JvmStatic
    @Throws(InvalidKeyException::class)
    fun calculateSignature(signingKey: ECPrivateKey?, message: ByteArray?): ByteArray {
      if (signingKey == null || message == null) {
        throw InvalidKeyException("Values must not be null")
      }

      return signingKey.calculateSignature(message)
    }
  }
}

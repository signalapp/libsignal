//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.util

import java.nio.charset.StandardCharsets

// This whole helper can go away when we reach Android 26, which supports java.util.Base64.
public class Base64 {
  public interface Impl {
    public fun decode(encoded: ByteArray): ByteArray

    public fun decodeUrl(encoded: ByteArray): ByteArray

    public fun encode(raw: ByteArray): String

    public fun encodeUrl(raw: ByteArray): String
  }

  companion object {
    @JvmStatic
    public fun decode(str: String): ByteArray = impl.decode(str.toByteArray(StandardCharsets.UTF_8))

    @JvmStatic
    public fun decodeUrl(str: String): ByteArray = impl.decodeUrl(str.toByteArray(StandardCharsets.UTF_8))

    @JvmStatic
    public fun encodeToString(input: ByteArray): String = impl.encode(input)

    @JvmStatic
    public fun encodeToStringUrl(input: ByteArray): String = impl.encodeUrl(input)

    val impl: Impl =
      run {
        // Prefer the Android class. If we preferred the JRE one, we'd only test the Android
        // codepath when testing on older emulators.
        try {
          try {
            var androidImpl = Class.forName("org.signal.libsignal.util.AndroidBase64")
            Impl::class.java.cast(androidImpl.getConstructor().newInstance())
          } catch (notFoundException: ClassNotFoundException) {
            JavaBase64
          }
        } catch (e: Exception) {
          throw AssertionError(e)
        }
      }
  }

  private object JavaBase64 : Impl {
    public override fun decode(encoded: ByteArray): ByteArray =
      java.util.Base64
        .getDecoder()
        .decode(encoded)

    public override fun decodeUrl(encoded: ByteArray): ByteArray =
      java.util.Base64
        .getUrlDecoder()
        .decode(encoded)

    public override fun encode(raw: ByteArray): String =
      java.util.Base64
        .getEncoder()
        .encodeToString(raw)

    public override fun encodeUrl(raw: ByteArray): String =
      java.util.Base64
        .getUrlEncoder()
        .withoutPadding()
        .encodeToString(raw)
  }
}

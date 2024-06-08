//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.util;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

// This whole helper can go away when we reach Android 26, which supports java.util.Base64.
public class Base64 {
  private static Function<byte[], byte[]> decodeImpl;

  static {
    // Prefer the Android class. If we preferred the JRE one, we'd only test the Android
    // codepath when testing on older emulators.
    try {
      try {
        Class<?> androidBase64 = Class.forName("android.util.Base64");
        // https://developer.android.com/reference/android/util/Base64#decode(byte[],%20int)
        Method decodeMethod = androidBase64.getDeclaredMethod("decode", byte[].class, int.class);
        decodeImpl =
            (input) -> {
              try {
                return (byte[]) decodeMethod.invoke(null, input, /*DEFAULT*/ 0);
              } catch (IllegalAccessException | InvocationTargetException e) {
                throw new AssertionError(e);
              }
            };

      } catch (ClassNotFoundException notFoundException) {
        Class<?> javaBase64 = Class.forName("java.util.Base64");
        // https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html#getDecoder--
        Method getDecoderMethod = javaBase64.getDeclaredMethod("getDecoder");
        Object decoder = getDecoderMethod.invoke(null);
        // https://docs.oracle.com/javase/8/docs/api/java/util/Base64.Decoder.html#decode-byte:A-
        Method decodeMethod = decoder.getClass().getDeclaredMethod("decode", byte[].class);
        decodeImpl =
            (input) -> {
              try {
                return (byte[]) decodeMethod.invoke(decoder, input);
              } catch (IllegalAccessException | InvocationTargetException e) {
                throw new AssertionError(e);
              }
            };
      }
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  public static byte[] decode(String str) {
    return decodeImpl.apply(str.getBytes(StandardCharsets.UTF_8));
  }
}

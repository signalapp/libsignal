package org.signal.libsignal.util

import android.util.Base64

public class AndroidBase64 : org.signal.libsignal.util.Base64.Impl {
  public override fun decode(encoded: ByteArray): ByteArray = Base64.decode(encoded, 0)

  public override fun decodeUrl(encoded: ByteArray): ByteArray = Base64.decode(encoded, Base64.URL_SAFE)

  public override fun encode(raw: ByteArray): String = Base64.encodeToString(raw, Base64.NO_WRAP)

  public override fun encodeUrl(raw: ByteArray): String =
    Base64.encodeToString(
      raw,
      Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE,
    )
}

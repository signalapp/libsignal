//
//  Copyright 2026 Signal Messenger, LLC
//  SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CalledFromNative
import java.net.URI
import java.net.URISyntaxException

public data class UploadForm(
  val cdn: Int,
  val key: String,
  val headers: Map<String, String>,
  val signedUploadUrl: URI,
) {
  public companion object {
    @JvmStatic
    @CalledFromNative
    public fun fromNative(
      cdn: Int,
      key: String,
      headers: Array<*>,
      signedUploadUrl: String,
    ): UploadForm =
      UploadForm(
        cdn = cdn,
        key = key,
        headers = (headers as Array<Pair<String, String>>).asList().toMap(),
        signedUploadUrl =
          try {
            URI(signedUploadUrl)
          } catch (_: URISyntaxException) {
            throw UnexpectedResponseException("Invalid URL for UploadForm's signedUploadUrl")
          },
      )
  }
}

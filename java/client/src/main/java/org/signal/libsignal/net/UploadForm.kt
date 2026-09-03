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
    @Suppress("UNCHECKED_CAST")
    private fun fromNative(
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

/**
 * The information needed for an upload to CDN0.
 *
 * Only the `key` is relevant to an application, as the CDN-relative path of the uploaded file.
 * Everything else should be passed through directly to AWS.
 */
public data class S3UploadForm(
  val key: String,
  val credential: String,
  val acl: String,
  val algorithm: String,
  val date: String,
  val policy: String,
  val signature: String,
) {
  /** Retrieves the properties in a known-working order for S3's POST-based upload. */
  public fun asHeaders(): List<Pair<String, String>> =
    listOf(
      "acl" to acl,
      "key" to key,
      "policy" to policy,
      "x-amz-algorithm" to algorithm,
      "x-amz-credential" to credential,
      "x-amz-date" to date,
      "x-amz-signature" to signature,
    )
}

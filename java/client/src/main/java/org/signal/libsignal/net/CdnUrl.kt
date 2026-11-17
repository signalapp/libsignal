//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.NativeNice

/**
 * A URL that points to a Signal CDN
 */
@ConsistentCopyVisibility
public data class CdnUrl private constructor(
  val url: String,
) {
  public companion object {
    // Public only for testing
    public fun libsignalOnlyFromPreValidatedString(url: String): CdnUrl = CdnUrl(url)

    /**
     * @throws IllegalArgumentException if the URL doesn't point at a Signal CDN
     */
    public fun fromString(url: String): CdnUrl {
      if (!NativeNice.CdnUrl_validate(url)) throw IllegalArgumentException("Illegal CDN URL")
      return CdnUrl(url)
    }
  }
}

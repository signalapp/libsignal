//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

public data class BadgeSvg(
  /**
   * File name of the scalable vector graphic for light mode.
   */
  public val light: String,
  /**
   * File name of the scalable vector graphic for dark mode.
   */
  public val dark: String,
)

public data class Badge(
  /**
   * An ID that uniquely identifies the badge.
   */
  public val id: String,
  /**
   * The category the badge falls in (such as "donor" or "other").
   */
  public val category: String,
  public val name: String,
  public val description: String,
  /**
   * File names of raster image sprite sheets
   *
   * Sprite sheets live at https://updates2.signal.org/static/badges/
   *
   * The sprite sheets are (in order) scaled at: 0.75x, 1x, 1.5x, 2x, 3x, 4x
   */
  public val sprites6: List<String>,
  /**
   * File name of the scalable vector graphic representing this badge, for the "transparent" theme
   *
   * SVGs live at https://updates2.signal.org/static/badges/
   */
  public val svg: String,
  /**
   * Pairs of light/dark SVG files designed for display at different sizes (in order: 16, 24, 36).
   *
   * SVGs live at https://updates2.signal.org/static/badges/
   */
  public val svgs: List<BadgeSvg>,
)

public data class TaggedBadges(
  /**
   * A map of badge ID to the detailed information for that badge.
   */
  public val badges: Map<String, Badge>,
  /**
   * An entity tag for `badges`. This may be supplied in a subsequent request
   * to optimize bandwidth when the set of badges has not changed.
   */
  public val etag: ByteArray,
) {
  // Since etag is a ByteArray
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as TaggedBadges

    if (badges != other.badges) return false
    if (!etag.contentEquals(other.etag)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = badges.hashCode()
    result = 31 * result + etag.contentHashCode()
    return result
  }
}

public class AuthRemoteConfigurationService(
  private val connection: AuthenticatedChatConnection,
) {
  /**
   * Returns detailed information for all configured badges, keyed by badge ID.
   *
   * Badge descriptions may contain localized strings. These are determined based on the Locale
   * of the `AuthenticatedChatConnection`.
   *
   * Callers may cache a badges result for up to 1 day before checking (via
   * etag) if there are any new updates.
   *
   * If the etag is up-to-date, this function will return null.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun getBadges(etag: ByteArray?): CompletableFuture<RequestResult<TaggedBadges?, Nothing>> =
    try {
      NativeNice
        .AuthenticatedChatConnection_get_badges(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          etag = etag,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(it) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}

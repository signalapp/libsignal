//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { StandardNetworkError } from '../../Errors.js';

export type Badge = {
  /**
   * An ID that uniquely identifies the badge.
   */
  id: string;
  /**
   * The category the badge falls in (such as "donor" or "other").
   */
  category: string;
  name: string;
  description: string;
  /**
   * File names of raster image sprite sheets
   *
   * Sprite sheets live at https://updates2.signal.org/static/badges/
   *
   * The sprite sheets are (in order) scaled at: 0.75x, 1x, 1.5x, 2x, 3x, 4x
   */
  sprites6: Array<string>;
  /**
   * File name of the scalable vector graphic representing this badge, for the "transparent" theme
   *
   * SVGs live at https://updates2.signal.org/static/badges/
   */
  svg: string;
  /**
   * Pairs of light/dark SVG files designed for display at different sizes (in order: 16, 24, 36).
   *
   * SVGs live at https://updates2.signal.org/static/badges/
   */
  svgs: Array<BadgeSvg>;
};

export type BadgeSvg = {
  /**
   * File name of the scalable vector graphic for light mode.
   */
  light: string;
  /**
   * File name of the scalable vector graphic for dark mode.
   */
  dark: string;
};

export type TaggedBadges = {
  /**
   * A map of badge ID to the detailed information for that badge.
   */
  badges: Map<string, Badge>;

  /**
   * An entity tag for `badges`. This may be supplied in a subsequent request
   * to optimize bandwidth when the set of badges has not changed.
   */
  etag: Uint8Array<ArrayBuffer>;
};

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection
    extends AuthRemoteConfigurationService {}
}

export interface AuthRemoteConfigurationService {
  /**
   * Returns detailed information for all configured badges, keyed by badge ID.
   *
   * Badge descriptions may contain localized strings. These are determined
   * based on the Locale of the `AuthenticatedChatConnection`.
   *
   * Callers may cache a badges result for up to 1 day before checking (via
   * etag) if there are any new updates.
   *
   * If the etag is up-to-date, this function will return null.
   *
   * @throws {StandardNetworkError}
   */
  getBadges: (
    request: { etag: Uint8Array<ArrayBuffer> | null },
    options?: RequestOptions
  ) => Promise<TaggedBadges | null>;
}
AuthenticatedChatConnection.prototype.getBadges = async function (
  {
    etag,
  }: {
    etag: Uint8Array<ArrayBuffer> | null;
  },
  options?: RequestOptions
): Promise<TaggedBadges | null> {
  return await NativeNice.AuthenticatedChatConnection_get_badges({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    etag,
  });
};

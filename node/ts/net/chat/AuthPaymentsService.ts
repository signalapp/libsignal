//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { StandardNetworkError } from '../../Errors.js';
import type { Timestamp } from '../../NiceConverters.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthPaymentsService {}
}

export type CurrencyConversions = {
  timestampMs: Timestamp;
  currencies: Array<Currency>;
};

export type Currency = {
  base: string;
  /**
   * The values of this map are decimal conversion rates.
   */
  conversions: Map<string, string>;
};

export interface AuthPaymentsService {
  /**
   * Return the current currency conversion rates.
   *
   * @throws {StandardNetworkError}
   */
  getCurrencyConversions: (
    options?: RequestOptions
  ) => Promise<CurrencyConversions>;
}
AuthenticatedChatConnection.prototype.getCurrencyConversions = async function (
  options?: RequestOptions
): Promise<CurrencyConversions> {
  const { timestampMs, currencies } =
    await NativeNice.AuthenticatedChatConnection_get_currency_conversions({
      asyncContext: this.asyncContext,
      abortSignal: options?.abortSignal,
      chat: this.chatService,
    });
  return {
    timestampMs,
    currencies: currencies.map(({ base, conversions }) => ({
      base,
      conversions: new Map(conversions),
    })),
  };
};

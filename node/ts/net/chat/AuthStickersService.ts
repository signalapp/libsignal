//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import {
  RequestOptions,
  AuthenticatedChatConnection,
  S3UploadForm,
} from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { StandardNetworkError } from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthStickersService {}
}

/** The output of {@link AuthStickersService#getStickerUploadForms}. */
export type GetStickerUploadFormsResponse = {
  /** A randomly-generated ID for the new sticker pack. */
  packId: string;
  /** An upload form clients must use to upload a manifest for the sticker pack. */
  manifestUploadForm: S3UploadForm;
  /** Upload forms for individual stickers within the sticker pack. */
  stickerUploadForms: S3UploadForm[];
};

export interface AuthStickersService {
  /**
   * Retrieve a set of upload forms that can be used to upload a sticker pack.
   *
   * A successful response is guaranteed to have the requested number of sticker upload forms.
   *
   * @param numberOfStickers Must be between 1 and 201 (inclusive).
   * @throws {StandardNetworkError}
   */
  getStickerUploadForms: (
    request: {
      numberOfStickers: number;
    },
    options?: RequestOptions
  ) => Promise<GetStickerUploadFormsResponse>;
}

AuthenticatedChatConnection.prototype.getStickerUploadForms = function (
  { numberOfStickers },
  options?: RequestOptions
): Promise<GetStickerUploadFormsResponse> {
  return NativeNice.AuthenticatedChatConnection_get_sticker_upload_forms({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    numberOfStickers,
  });
};

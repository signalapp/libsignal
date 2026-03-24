//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as Native from '../../Native.js';
import { LibSignalErrorBase } from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthMessagesService {}
}

export type UploadForm = {
  cdn: number;
  key: string;
  headers: Map<string, string>;
  signedUploadUrl: URL;
};

export interface AuthMessagesService {
  /**
   * Get an attachment upload form
   *
   * Throws / completes with failure only if the request can't be completed.
   */
  getUploadForm: (options?: RequestOptions) => Promise<UploadForm>;
}

AuthenticatedChatConnection.prototype.getUploadForm = async function (
  options?: RequestOptions
): Promise<UploadForm> {
  const { cdn, key, headers, signedUploadUrl } =
    await this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.AuthenticatedChatConnection_get_upload_form(
        this.asyncContext,
        this.chatService
      )
    );
  let signedUploadUrlConverted;
  try {
    signedUploadUrlConverted = new URL(signedUploadUrl);
  } catch (e) {
    throw new LibSignalErrorBase(
      `Invalid URL for getUploadForm: ${e}`,
      'Generic',
      'getUploadForm'
    );
  }
  return {
    cdn: cdn,
    key: key,
    headers: new Map(headers),
    signedUploadUrl: signedUploadUrlConverted,
  };
};

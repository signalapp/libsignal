//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { StandardNetworkError } from '../../Errors.js';
import { Aci } from '../../Address.js';
import type { S3UploadForm } from '../Chat.js';
import * as zkgroup from '../../zkgroup/index.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthProfilesService {}
}

export interface AuthProfilesService {
  /**
   * Returns a form to upload a legacy (v1) avatar.
   *
   * @throws {StandardNetworkError}
   */
  getAvatarUploadFormLegacy: (
    request: {
      aci: Aci;
      profileKey: zkgroup.ProfileKey;
    },
    options?: RequestOptions
  ) => Promise<S3UploadForm>;
}

AuthenticatedChatConnection.prototype.getAvatarUploadFormLegacy =
  async function (
    {
      aci,
      profileKey,
    }: {
      aci: Aci;
      profileKey: zkgroup.ProfileKey;
    },
    options?: RequestOptions
  ): Promise<S3UploadForm> {
    return await NativeNice.AuthenticatedChatConnection_get_avatar_upload_form_legacy(
      {
        asyncContext: this.asyncContext,
        abortSignal: options?.abortSignal,
        chat: this.chatService,
        aci,
        profileKey,
      }
    );
  };

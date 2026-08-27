//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type { InvalidReceiptError, MissingBackupId } from '../../Errors.js';
import type { ReceiptCredentialPresentation } from '../../zkgroup/index.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthBackupsService {}
}

export interface AuthBackupsService {
  /**
   * Redeem a receipt to mark the account as eligible for the paid backup tier.
   *
   * After successful redemption, fetched BackupAuthCredentials will include the level on the
   * provided receipt until the expiration time on the receipt.
   *
   * @throws {InvalidReceiptError} if the receipt is invalid or expired.
   * @throws {MissingBackupId} if there is no backup ID on the account.
   */
  redeemBackupReceipt: (
    request: {
      presentation: ReceiptCredentialPresentation;
    },
    options?: RequestOptions
  ) => Promise<void>;
}

AuthenticatedChatConnection.prototype.redeemBackupReceipt = async function (
  { presentation },
  options?
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_redeem_backup_receipt({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    presentation,
  });
};

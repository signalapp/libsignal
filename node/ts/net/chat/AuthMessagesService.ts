//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import {
  RequestOptions,
  AuthenticatedChatConnection,
  type UploadForm,
} from '../Chat.js';
import * as Native from '../../Native.js';
import { LibSignalErrorBase } from '../../Errors.js';
import { ServiceId } from '../../Address.js';
import { type SingleOutboundUnsealedMessage } from './SingleOutboundMessage.js';
import { type CiphertextMessage } from '../../CiphertextMessage.js';

// For documentation
import type {
  ChatServiceInactive,
  IoError,
  MismatchedDevicesEntry,
  MismatchedDevicesError,
  RateLimitedError,
  RateLimitChallengeError,
  ServiceIdNotFound,
  UploadTooLarge,
} from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthMessagesService {}
}

/** See {@link AuthMessagesService#sendMessage}. */
export type SendMessageRequest = Readonly<{
  destination: ServiceId;
  timestamp: number;
  contents: Readonly<SingleOutboundUnsealedMessage[]>;
  onlineOnly: boolean;
  urgent: boolean;
}>;

/** See {@link AuthMessagesService#sendSyncMessage}. */
export type SendSyncMessageRequest = Readonly<{
  timestamp: number;
  contents: Readonly<SingleOutboundUnsealedMessage[]>;
  urgent: boolean;
}>;

export interface AuthMessagesService {
  /**
   * Get an attachment upload form
   *
   * @throws {UploadTooLarge} if `uploadSize` is too large
   */
  getUploadForm: (
    request: { uploadSize: bigint },
    options?: RequestOptions
  ) => Promise<UploadForm>;

  /**
   * Sends a 1:1 unsealed message.
   *
   * @throws {MismatchedDevicesError} if the recipient devices specified in `contents` are out of
   * date in some way. This is not a "partial success" result; the message has not been sent to
   * anybody.
   * @throws {ServiceIdNotFound} if the destination account has been unregistered.
   * @throws {RateLimitChallengeError} if a challenge must be completed before sending this message.
   * @throws {ChatServiceInactive} if the chat connection has been closed.
   * @throws {IoError} if an error occurred while communicating with the server.
   * @throws {RateLimitedError} if the server is rate limiting this client. This is **retryable**
   * after waiting the designated delay.
   *
   * @see {@link MismatchedDevicesEntry}
   */
  sendMessage: (
    request: SendMessageRequest,
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Sends a 1:1 message to linked devices.
   *
   * @throws {MismatchedDevicesError} if the recipient devices specified in `contents` are out of
   * date in some way. This is not a "partial success" result; the message has not been sent to
   * anybody.
   * @throws {RateLimitChallengeError} if a challenge must be completed before sending this message.
   * @throws {ChatServiceInactive} if the chat connection has been closed.
   * @throws {IoError} if an error occurred while communicating with the server.
   * @throws {RateLimitedError} if the server is rate limiting this client. This is **retryable**
   * after waiting the designated delay.
   *
   * @see {@link MismatchedDevicesEntry}
   */
  sendSyncMessage: (
    request: SendSyncMessageRequest,
    options?: RequestOptions
  ) => Promise<void>;
}

AuthenticatedChatConnection.prototype.getUploadForm = async function (
  { uploadSize }: { uploadSize: bigint },
  options?: RequestOptions
): Promise<UploadForm> {
  const { cdn, key, headers, signedUploadUrl } =
    await this.asyncContext.makeCancellable(
      options?.abortSignal,
      Native.AuthenticatedChatConnection_get_upload_form(
        this.asyncContext,
        this.chatService,
        uploadSize
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

AuthenticatedChatConnection.prototype.sendMessage = async function (
  { destination, timestamp, contents, onlineOnly, urgent }: SendMessageRequest,
  options?: RequestOptions
): Promise<void> {
  const deviceIds = new Uint32Array(contents.length);
  const registrationIds = new Uint32Array(contents.length);
  const messages: CiphertextMessage[] = [];
  contents.forEach((next, i) => {
    deviceIds[i] = next.deviceId;
    registrationIds[i] = next.registrationId;
    messages.push(next.contents);
  });

  await this.asyncContext.makeCancellable(
    options?.abortSignal,
    Native.AuthenticatedChatConnection_send_message(
      this.asyncContext,
      this.chatService,
      destination.getServiceIdFixedWidthBinary(),
      timestamp,
      deviceIds,
      registrationIds,
      messages,
      onlineOnly,
      urgent
    )
  );
};

AuthenticatedChatConnection.prototype.sendSyncMessage = async function (
  { timestamp, contents, urgent }: SendSyncMessageRequest,
  options?: RequestOptions
): Promise<void> {
  const deviceIds = new Uint32Array(contents.length);
  const registrationIds = new Uint32Array(contents.length);
  const messages: CiphertextMessage[] = [];
  contents.forEach((next, i) => {
    deviceIds[i] = next.deviceId;
    registrationIds[i] = next.registrationId;
    messages.push(next.contents);
  });

  await this.asyncContext.makeCancellable(
    options?.abortSignal,
    Native.AuthenticatedChatConnection_send_sync_message(
      this.asyncContext,
      this.chatService,
      timestamp,
      deviceIds,
      registrationIds,
      messages,
      urgent
    )
  );
};

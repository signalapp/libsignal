//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../../Native.js';
import { ServiceId } from '../../Address.js';
import { RequestOptions, UnauthenticatedChatConnection } from '../Chat.js';
import { GroupSendFullToken } from '../../zkgroup/index.js';
import { SingleOutboundSealedSenderMessage } from './SingleOutboundMessage.js';

// For documentation
import type {
  MismatchedDevicesEntry,
  MismatchedDevicesError,
  RequestUnauthorizedError,
  ChatServiceInactive,
  IoError,
  RateLimitedError,
  ServiceIdNotFound,
} from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthMessagesService {}
}

/** See {@link UnauthMessagesService#sendMultiRecipientMessage}. */
export type MultiRecipientMessageRequest = Readonly<{
  payload: Uint8Array<ArrayBuffer>;
  timestamp: number;
  auth: 'story' | GroupSendFullToken;
  onlineOnly: boolean;
  urgent: boolean;
}>;

/**
 * Successful response for {@link UnauthMessagesService#sendMultiRecipientMessage}.
 *
 * When authenticating using a {@link GroupSendFullToken}, the server will report which recipients
 * are currently unregistered. For `story` auth the list will always be empty.
 */
export class MultiRecipientMessageResponse {
  constructor(public unregisteredIds: ServiceId[]) {}
}

/** See {@link UnauthMessagesService#sendMessage}. */
export type SendSealedMessageRequest = Readonly<{
  destination: ServiceId;
  timestamp: number;
  contents: Readonly<SingleOutboundSealedSenderMessage[]>;
  auth:
    | 'story'
    | { accessKey: Uint8Array<ArrayBuffer> }
    | GroupSendFullToken
    | 'unrestricted';
  onlineOnly: boolean;
  urgent: boolean;
}>;

export interface UnauthMessagesService {
  /**
   * Sends a multi-recipient message encrypted with Sealed Sender v2.
   *
   * Messages to accounts that have been unregistered will be dropped by the server and (if using
   * {@link GroupSendFullToken}-based auth) reported in the resulting
   * {@link MultiRecipientMessageResponse}.
   *
   * @throws {RequestUnauthorizedError} if `auth` is not valid for the recipients specified in
   * `payload`. (This cannot happen when `auth` is `'story'`.)
   * @throws {MismatchedDevicesError} if the recipient devices specified in `payload` are out of
   * date in some way. This is not a "partial success" result; the message has not been sent to
   * anybody.
   * @throws {ChatServiceInactive} if the chat connection has been closed.
   * @throws {IoError} if an error occurred while communicating with the server.
   * @throws {RateLimitedError} if the server is rate limiting this client. This is **retryable**
   * after waiting the designated delay.
   *
   * @see `sealedSenderMultiRecipientEncrypt`
   * @see {@link MismatchedDevicesEntry}
   */
  sendMultiRecipientMessage: (
    request: MultiRecipientMessageRequest,
    options?: RequestOptions
  ) => Promise<MultiRecipientMessageResponse>;

  /**
   * Sends a 1:1 message encrypted with Sealed Sender.
   *
   * @throws {RequestUnauthorizedError} if `auth` is not valid for the recipients specified in
   * `payload`. (This cannot happen when `auth` is `'story'`.)
   * @throws {MismatchedDevicesError} if the recipient devices specified in `payload` are out of
   * date in some way. This is not a "partial success" result; the message has not been sent to
   * anybody.
   * @throws {ServiceIdNotFound} if the destination account has been unregistered.
   * @throws {ChatServiceInactive} if the chat connection has been closed.
   * @throws {IoError} if an error occurred while communicating with the server.
   * @throws {RateLimitedError} if the server is rate limiting this client. This is **retryable**
   * after waiting the designated delay.
   *
   * @see `sealedSenderEncrypt`
   * @see {@link MismatchedDevicesEntry}
   */
  sendMessage: (
    request: SendSealedMessageRequest,
    options?: RequestOptions
  ) => Promise<void>;
}

UnauthenticatedChatConnection.prototype.sendMultiRecipientMessage =
  async function (
    {
      payload,
      timestamp,
      auth,
      onlineOnly,
      urgent,
    }: MultiRecipientMessageRequest,
    options?: RequestOptions
  ): Promise<MultiRecipientMessageResponse> {
    const response = await this._asyncContext.makeCancellable(
      options?.abortSignal,
      Native.UnauthenticatedChatConnection_send_multi_recipient_message(
        this._asyncContext,
        this._chatService,
        payload,
        timestamp,
        auth === 'story' ? null : auth.getContents(),
        onlineOnly,
        urgent
      )
    );
    return new MultiRecipientMessageResponse(
      response.map((raw) => ServiceId.parseFromServiceIdFixedWidthBinary(raw))
    );
  };

UnauthenticatedChatConnection.prototype.sendMessage = async function (
  {
    destination,
    timestamp,
    contents,
    auth,
    onlineOnly,
    urgent,
  }: SendSealedMessageRequest,
  options?: RequestOptions
): Promise<void> {
  const deviceIds = new Uint32Array(contents.length);
  const registrationIds = new Uint32Array(contents.length);
  const messages: Uint8Array<ArrayBuffer>[] = [];
  contents.forEach((next, i) => {
    deviceIds[i] = next.deviceId;
    registrationIds[i] = next.registrationId;
    messages.push(next.contents);
  });

  // Must be kept in sync with `UserBasedSendAuthorizationKind` in Rust.
  const enum AuthKind {
    Story,
    AccessKey,
    GroupSend,
    UnrestrictedUnidentifiedAccess,
  }

  let authKind: AuthKind;
  let authPayload: Uint8Array<ArrayBuffer> | null;
  if (auth === 'story') {
    authKind = AuthKind.Story;
    authPayload = null;
  } else if (auth === 'unrestricted') {
    authKind = AuthKind.UnrestrictedUnidentifiedAccess;
    authPayload = null;
  } else if (auth instanceof GroupSendFullToken) {
    authKind = AuthKind.GroupSend;
    authPayload = auth.contents;
  } else {
    authKind = AuthKind.AccessKey;
    authPayload = auth.accessKey;
  }

  await this._asyncContext.makeCancellable(
    options?.abortSignal,
    Native.UnauthenticatedChatConnection_send_message(
      this._asyncContext,
      this._chatService,
      destination.getServiceIdFixedWidthBinary(),
      timestamp,
      deviceIds,
      registrationIds,
      messages,
      authKind,
      authPayload,
      onlineOnly,
      urgent
    )
  );
};

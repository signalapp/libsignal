//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { type CiphertextMessage } from '../../CiphertextMessage.js';

/**
 * A message to send to a single device of a peer.
 *
 * Used by APIs like `UnauthMessagesService.sendMessage`.
 */
export type SingleOutboundMessage<T> = Readonly<{
  deviceId: number;
  registrationId: number;
  contents: T;
}>;

export type SingleOutboundSealedSenderMessage = SingleOutboundMessage<
  Uint8Array<ArrayBuffer>
>;
export type SingleOutboundUnsealedMessage =
  SingleOutboundMessage<CiphertextMessage>;

//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

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

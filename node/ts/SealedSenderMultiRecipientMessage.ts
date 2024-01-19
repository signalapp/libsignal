//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native';

/**
 * A single recipient parsed from a {@link SealedSenderMultiRecipientMessage}.
 *
 * The `deviceIds` and `registrationIds` arrays are parallel (so the first entry of each belongs to
 * one device, the second to another, and so on).
 */
export interface Recipient {
  deviceIds: number[];
  registrationIds: number[];
}

/**
 * A parsed Sealed Sender v2 "SentMessage", ready to be fanned out to multiple recipients.
 *
 * The implementation assumes that every device for a particular recipient should use the same key
 * material.
 */
export default class SealedSenderMultiRecipientMessage {
  readonly _buffer: Buffer;
  readonly _recipientMap: {
    [serviceId: string]: Native.SealedSenderMultiRecipientMessageRecipient;
  };
  readonly _excludedRecipients: string[];
  readonly _offsetOfSharedData: number;

  constructor(buffer: Buffer) {
    const { recipientMap, excludedRecipients, offsetOfSharedData } =
      Native.SealedSenderMultiRecipientMessage_Parse(buffer);
    this._buffer = buffer;
    this._recipientMap = recipientMap;
    this._excludedRecipients = excludedRecipients;
    this._offsetOfSharedData = offsetOfSharedData;
  }

  /**
   * Returns the recipients parsed from the message, keyed by service ID string.
   *
   * The result has no keys other than the service IDs of the recipients.
   */
  recipientsByServiceIdString(): Readonly<{ [serviceId: string]: Recipient }> {
    return this._recipientMap;
  }

  /**
   * Returns the service IDs of recipients excluded from receiving the message.
   *
   * This is enforced to be disjoint from the recipients in {@link #recipientsByServiceIdString}; it
   * may be used for authorization purposes or just to check that certain recipients were
   * deliberately excluded rather than accidentally.
   */
  excludedRecipientServiceIdStrings(): ReadonlyArray<string> {
    return this._excludedRecipients;
  }

  /**
   * Returns the Sealed Sender V2 "ReceivedMessage" payload for delivery to a particular recipient.
   *
   * `recipient` must be one of the recipients in the map returned by
   * {@link #recipientsByServiceIdString}. The same payload should be sent to all of the recipient's
   * devices.
   */
  messageForRecipient(recipient: Recipient): Buffer {
    const nativeRecipient =
      recipient as Native.SealedSenderMultiRecipientMessageRecipient;
    return Buffer.concat([
      Buffer.of(0x22), // The "original" Sealed Sender V2 version
      this._buffer.subarray(
        nativeRecipient.rangeOffset,
        nativeRecipient.rangeOffset + nativeRecipient.rangeLen
      ),
      this._buffer.subarray(this._offsetOfSharedData),
    ]);
  }
}

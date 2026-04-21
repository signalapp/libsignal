//
// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.protocol.message.CiphertextMessage

/**
 * A message to send to a single device of a peer.
 *
 * Used by APIs like [UnauthMessagesService.sendMessage].
 */
public data class SingleOutboundMessage<T>(
  public val deviceId: Int,
  public val registrationId: Int,
  public val message: T,
)

public typealias SingleOutboundSealedSenderMessage = SingleOutboundMessage<ByteArray>
public typealias SingleOutboundUnsealedMessage = SingleOutboundMessage<CiphertextMessage>

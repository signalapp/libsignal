//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

open class NoOpListener : ChatConnectionListener {
  override fun onIncomingMessage(
    chat: ChatConnection,
    envelope: ByteArray,
    serverDeliveryTimestamp: Long,
    sendAck: ChatConnectionListener.ServerMessageAck,
  ) {}
}

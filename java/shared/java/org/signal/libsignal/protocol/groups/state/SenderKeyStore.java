/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.groups.state;

import org.signal.libsignal.protocol.SignalProtocolAddress;

import java.util.UUID;

public interface SenderKeyStore {

  /**
   * Commit to storage the {@link org.signal.libsignal.protocol.groups.state.SenderKeyRecord} for a
   * given (distributionId + senderName + deviceId) tuple.
   *
   * @param sender The address of the current client.
   * @param distributionId An opaque identifier that uniquely identifies the group (but isn't the group ID).
   * @param record the current SenderKeyRecord for the specified (distributionId + senderName + deviceId) tuple.
   */
  public void storeSenderKey(SignalProtocolAddress sender, UUID distributionId, SenderKeyRecord record);

  /**
   * Returns a copy of the {@link org.signal.libsignal.protocol.groups.state.SenderKeyRecord}
   * corresponding to the (distributionId + senderName + deviceId) tuple, or `null` if one does not 
   * exist.
   * 
   * It is important that implementations return a copy of the current durable information.  The
   * returned SenderKeyRecord may be modified, but those changes should not have an effect on the
   * durable session state (what is returned by subsequent calls to this method) without the
   * store method being called here first.
   *
   * @param sender The address of the current client.
   * @param distributionId An opaque identifier that uniquely identifies the group (but isn't the group ID).
   * @return a copy of the SenderKeyRecord corresponding to the (id + senderName + deviceId tuple, or
   *         `null` if one does not currently exist.
   */
  public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender, UUID distributionId);
}

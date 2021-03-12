/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;

import java.util.UUID;

/**
 * GroupSessionBuilder is responsible for setting up group SenderKey encrypted sessions.
 *
 * Once a session has been established, {@link org.whispersystems.libsignal.groups.GroupCipher}
 * can be used to encrypt/decrypt messages in that session.
 * <p>
 * The built sessions are unidirectional: they can be used either for sending or for receiving,
 * but not both.
 *
 * Sessions are constructed per (senderName + deviceId) tuple, with sending additionally 
 * parameterized on a per-group distributionId. Remote logical users are identified by their 
 * senderName, and each logical user can have multiple physical devices.
 *
 * This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */

public class GroupSessionBuilder {
  private final SenderKeyStore senderKeyStore;

  public GroupSessionBuilder(SenderKeyStore senderKeyStore) {
    this.senderKeyStore = senderKeyStore;
  }

  /**
   * Construct a group session for receiving messages from sender.
   *
   * @param sender The address of the device that sent the message.
   * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
   */
  public void process(SignalProtocolAddress sender, SenderKeyDistributionMessage senderKeyDistributionMessage) {
    Native.GroupSessionBuilder_ProcessSenderKeyDistributionMessage(sender.nativeHandle(),
                                                                   senderKeyDistributionMessage.nativeHandle(),
                                                                   senderKeyStore, null);
  }

  /**
   * Construct a group session for sending messages.
   *
   * @param sender The address of the current client.
   * @param distributionId An opaque identifier that uniquely identifies the group (but isn't the group ID).
   * @return A SenderKeyDistributionMessage that is individually distributed to each member of the group.
   */
  public SenderKeyDistributionMessage create(SignalProtocolAddress sender, UUID distributionId) {
    return new SenderKeyDistributionMessage(Native.GroupSessionBuilder_CreateSenderKeyDistributionMessage(sender.nativeHandle(), distributionId, senderKeyStore, null));
  }
}

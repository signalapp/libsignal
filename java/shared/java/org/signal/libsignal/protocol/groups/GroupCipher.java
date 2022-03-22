/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.groups;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.DuplicateMessageException;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.groups.state.SenderKeyStore;
import org.signal.libsignal.protocol.message.CiphertextMessage;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * The main entry point for Signal Protocol group encrypt/decrypt operations.
 *
 * Once a session has been established with {@link org.signal.libsignal.protocol.groups.GroupSessionBuilder}
 * and a {@link org.signal.libsignal.protocol.message.SenderKeyDistributionMessage} has been
 * distributed to each member of the group, this class can be used for all subsequent encrypt/decrypt
 * operations within that session (ie: until group membership changes).
 *
 * This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class GroupCipher {

  private final SenderKeyStore senderKeyStore;
  private final SignalProtocolAddress sender;

  public GroupCipher(SenderKeyStore senderKeyStore, SignalProtocolAddress sender) {
    this.senderKeyStore = senderKeyStore;
    this.sender         = sender;
  }

  /**
   * Encrypt a message.
   *
   * @param paddedPlaintext The plaintext message bytes, optionally padded.
   * @return Ciphertext.
   * @throws NoSessionException
   */
  public CiphertextMessage encrypt(UUID distributionId, byte[] paddedPlaintext) throws NoSessionException {
    try (NativeHandleGuard sender = new NativeHandleGuard(this.sender)) {
      return Native.GroupCipher_EncryptMessage(sender.nativeHandle(), distributionId, paddedPlaintext, this.senderKeyStore, null);
    }
  }

  /**
   * Decrypt a SenderKey group message.
   *
   * @param senderKeyMessageBytes The received ciphertext.
   * @return Plaintext
   * @throws LegacyMessageException
   * @throws InvalidMessageException
   * @throws DuplicateMessageException
   */
  public byte[] decrypt(byte[] senderKeyMessageBytes)
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
  {
    try (NativeHandleGuard sender = new NativeHandleGuard(this.sender)) {
      return Native.GroupCipher_DecryptMessage(sender.nativeHandle(), senderKeyMessageBytes, this.senderKeyStore, null);
    }
  }
}

/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.PreKeySignalMessage;
import org.signal.libsignal.protocol.message.SignalMessage;
import org.signal.libsignal.protocol.state.SignalProtocolStore;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.PreKeyStore;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.SessionStore;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * The main entry point for Signal Protocol encrypt/decrypt operations.
 *
 * Once a session has been established with {@link SessionBuilder},
 * this class can be used for all encrypt/decrypt operations within
 * that session.
 *
 * This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class SessionCipher {

  private final SessionStore          sessionStore;
  private final IdentityKeyStore      identityKeyStore;
  private final PreKeyStore           preKeyStore;
  private final SignedPreKeyStore     signedPreKeyStore;
  private final KyberPreKeyStore      kyberPreKeyStore;
  private final SignalProtocolAddress remoteAddress;

  /**
   * Construct a SessionCipher for encrypt/decrypt operations on a session.
   * In order to use SessionCipher, a session must have already been created
   * and stored using {@link SessionBuilder}.
   *
   * @param  sessionStore The {@link SessionStore} that contains a session for this recipient.
   * @param  remoteAddress  The remote address that messages will be encrypted to or decrypted from.
   */
  public SessionCipher(SessionStore sessionStore,
                       PreKeyStore preKeyStore,
                       SignedPreKeyStore signedPreKeyStore,
                       KyberPreKeyStore kyberPreKeyStore,
                       IdentityKeyStore identityKeyStore,
                       SignalProtocolAddress remoteAddress)
  {
    this.sessionStore      = sessionStore;
    this.preKeyStore       = preKeyStore;
    this.identityKeyStore  = identityKeyStore;
    this.remoteAddress     = remoteAddress;
    this.signedPreKeyStore = signedPreKeyStore;
    this.kyberPreKeyStore  = kyberPreKeyStore;;
  }

  public SessionCipher(SignalProtocolStore store, SignalProtocolAddress remoteAddress) {
    this(store, store, store, store, store, remoteAddress);
  }

  /**
   * Encrypt a message.
   *
   * @param  paddedMessage The plaintext message bytes, optionally padded to a constant multiple.
   * @return A ciphertext message encrypted to the recipient+device tuple.
   */
  public CiphertextMessage encrypt(byte[] paddedMessage) throws UntrustedIdentityException {
    try (NativeHandleGuard remoteAddress = new NativeHandleGuard(this.remoteAddress)) {
      return Native.SessionCipher_EncryptMessage(paddedMessage,
                                                 remoteAddress.nativeHandle(),
                                                 sessionStore,
                                                 identityKeyStore,
                                                 null);
    }
  }

  /**
   * Decrypt a message.
   *
   * @param  ciphertext The {@link PreKeySignalMessage} to decrypt.
   *
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws InvalidKeyIdException when there is no local {@link org.signal.libsignal.protocol.state.PreKeyRecord}
   *                               that corresponds to the PreKey ID in the message.
   * @throws InvalidKeyException when the message is formatted incorrectly.
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
   */
  public byte[] decrypt(PreKeySignalMessage ciphertext)
      throws DuplicateMessageException, InvalidMessageException, InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException
  {
    try (
      NativeHandleGuard ciphertextGuard = new NativeHandleGuard(ciphertext);
      NativeHandleGuard remoteAddressGuard = new NativeHandleGuard(this.remoteAddress);
    ) {
      return Native.SessionCipher_DecryptPreKeySignalMessage(ciphertextGuard.nativeHandle(),
                                                             remoteAddressGuard.nativeHandle(),
                                                             sessionStore,
                                                             identityKeyStore,
                                                             preKeyStore,
                                                             signedPreKeyStore,
                                                             kyberPreKeyStore,
                                                             null);
    }
  }

  /**
   * Decrypt a message.
   *
   * @param  ciphertext The {@link SignalMessage} to decrypt.
   *
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws InvalidVersionException if the message version does not match the session version.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws NoSessionException if there is no established session for this contact.
   */
  public byte[] decrypt(SignalMessage ciphertext)
      throws InvalidMessageException, InvalidVersionException, DuplicateMessageException, NoSessionException, UntrustedIdentityException
  {
    try (
      NativeHandleGuard ciphertextGuard = new NativeHandleGuard(ciphertext);
      NativeHandleGuard remoteAddressGuard = new NativeHandleGuard(this.remoteAddress);
    ) {
      return Native.SessionCipher_DecryptSignalMessage(ciphertextGuard.nativeHandle(),
                                                       remoteAddressGuard.nativeHandle(),
                                                       sessionStore,
                                                       identityKeyStore,
                                                       null);
    }
  }

  public int getRemoteRegistrationId() {
    if (!sessionStore.containsSession(remoteAddress)) {
      throw new IllegalStateException(String.format("No session for (%s)!", remoteAddress));
    }

    SessionRecord record = sessionStore.loadSession(remoteAddress);
    return record.getRemoteRegistrationId();
  }

  public int getSessionVersion() {
    if (!sessionStore.containsSession(remoteAddress)) {
      throw new IllegalStateException(String.format("No session for (%s)!", remoteAddress));
    }

    SessionRecord record = sessionStore.loadSession(remoteAddress);
    return record.getSessionVersion();
  }
}

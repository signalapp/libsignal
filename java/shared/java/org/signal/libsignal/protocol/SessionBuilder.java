//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.PreKeyStore;
import org.signal.libsignal.protocol.state.SessionStore;
import org.signal.libsignal.protocol.state.SignalProtocolStore;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;

/**
 * SessionBuilder is responsible for setting up encrypted sessions. Once a session has been
 * established, {@link org.signal.libsignal.protocol.SessionCipher} can be used to encrypt/decrypt
 * messages in that session.
 *
 * <p>Sessions are built from one of two different possible vectors:
 *
 * <ol>
 *   <li>A {@link org.signal.libsignal.protocol.state.PreKeyBundle} retrieved from a server.
 *   <li>A {@link org.signal.libsignal.protocol.message.PreKeySignalMessage} received from a client.
 * </ol>
 *
 * Only the first, however, is handled by SessionBuilder.
 *
 * <p>Sessions are constructed per recipientId + deviceId tuple. Remote logical users are identified
 * by their recipientId, and each logical recipientId can have multiple physical devices.
 *
 * <p>This class is not thread-safe.
 *
 * @author Moxie Marlinspike
 */
public class SessionBuilder {
  private static final String TAG = SessionBuilder.class.getSimpleName();

  private final SessionStore sessionStore;
  private final PreKeyStore preKeyStore;
  private final SignedPreKeyStore signedPreKeyStore;
  private final IdentityKeyStore identityKeyStore;
  private final SignalProtocolAddress remoteAddress;

  /**
   * Constructs a SessionBuilder.
   *
   * @param sessionStore The {@link org.signal.libsignal.protocol.state.SessionStore} to store the
   *     constructed session in.
   * @param preKeyStore The {@link org.signal.libsignal.protocol.state.PreKeyStore} where the
   *     client's local {@link org.signal.libsignal.protocol.state.PreKeyRecord}s are stored.
   * @param identityKeyStore The {@link org.signal.libsignal.protocol.state.IdentityKeyStore}
   *     containing the client's identity key information.
   * @param remoteAddress The address of the remote user to build a session with.
   */
  public SessionBuilder(
      SessionStore sessionStore,
      PreKeyStore preKeyStore,
      SignedPreKeyStore signedPreKeyStore,
      IdentityKeyStore identityKeyStore,
      SignalProtocolAddress remoteAddress) {
    this.sessionStore = sessionStore;
    this.preKeyStore = preKeyStore;
    this.signedPreKeyStore = signedPreKeyStore;
    this.identityKeyStore = identityKeyStore;
    this.remoteAddress = remoteAddress;
  }

  /**
   * Constructs a SessionBuilder
   *
   * @param store The {@link SignalProtocolStore} to store all state information in.
   * @param remoteAddress The address of the remote user to build a session with.
   */
  public SessionBuilder(SignalProtocolStore store, SignalProtocolAddress remoteAddress) {
    this(store, store, store, store, remoteAddress);
  }

  /**
   * Build a new session from a {@link org.signal.libsignal.protocol.state.PreKeyBundle} retrieved
   * from a server.
   *
   * @param preKey A PreKey for the destination recipient, retrieved from a server.
   * @throws InvalidKeyException when the {@link org.signal.libsignal.protocol.state.PreKeyBundle}
   *     is badly formatted.
   * @throws org.signal.libsignal.protocol.UntrustedIdentityException when the sender's {@link
   *     IdentityKey} is not trusted.
   */
  public void process(PreKeyBundle preKey) throws InvalidKeyException, UntrustedIdentityException {
    process(preKey, Instant.now());
  }

  /**
   * Build a new session from a {@link org.signal.libsignal.protocol.state.PreKeyBundle} retrieved
   * from a server.
   *
   * <p>You should only use this overload if you need to test session expiration explicitly.
   *
   * @param preKey A PreKey for the destination recipient, retrieved from a server.
   * @param now The current time, used later to check if the session is stale.
   * @throws InvalidKeyException when the {@link org.signal.libsignal.protocol.state.PreKeyBundle}
   *     is badly formatted.
   * @throws org.signal.libsignal.protocol.UntrustedIdentityException when the sender's {@link
   *     IdentityKey} is not trusted.
   */
  public void process(PreKeyBundle preKey, Instant now)
      throws InvalidKeyException, UntrustedIdentityException {
    try (NativeHandleGuard preKeyGuard = new NativeHandleGuard(preKey);
        NativeHandleGuard remoteAddressGuard = new NativeHandleGuard(this.remoteAddress)) {
      filterExceptions(
          InvalidKeyException.class,
          UntrustedIdentityException.class,
          () ->
              Native.SessionBuilder_ProcessPreKeyBundle(
                  preKeyGuard.nativeHandle(),
                  remoteAddressGuard.nativeHandle(),
                  sessionStore,
                  identityKeyStore,
                  now.toEpochMilli()));
    }
  }
}

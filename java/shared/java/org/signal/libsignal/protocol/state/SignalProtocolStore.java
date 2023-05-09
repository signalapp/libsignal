/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.state;

import org.signal.libsignal.protocol.groups.state.SenderKeyStore;

public interface SignalProtocolStore
    extends IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore, SenderKeyStore, KyberPreKeyStore
{
}

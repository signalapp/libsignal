//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import org.signal.libsignal.protocol.groups.state.SenderKeyStore;

public interface SignalProtocolStore
    extends IdentityKeyStore,
        PreKeyStore,
        SessionStore,
        SignedPreKeyStore,
        SenderKeyStore,
        KyberPreKeyStore {}

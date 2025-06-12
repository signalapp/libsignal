//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

/**
 * The public parts of a {@link org.signal.libsignal.protocol.state.SignedPreKeyRecord} or {@link
 * org.signal.libsignal.protocol.state.KyberPreKeyRecord}.
 *
 * <p>This is what gets uploaded when setting pre-keys while registering an account.
 */
public record SignedPublicPreKey<Key extends SerializablePublicKey>(
    int id, Key publicKey, byte[] signature) {}

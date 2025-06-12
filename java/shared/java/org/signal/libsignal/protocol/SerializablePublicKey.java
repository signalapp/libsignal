//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import org.signal.libsignal.internal.NativeHandleGuard;

/**
 * Marker interface for public key types compatible with native code.
 *
 * <p>This is only implemented by {@link org.signal.libsignal.protocol.ecc.ECPublicKey} and {@link
 * org.signal.libsignal.protocol.kem.KEMPublicKey}. If that changes, the corresponding Rust
 * conversion code should be updated.
 */
public interface SerializablePublicKey extends NativeHandleGuard.Owner {}

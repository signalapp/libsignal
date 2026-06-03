//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/** The public half of a {@link ZkCredentialKeyPair}. */
public final class ZkCredentialPublicKey extends ByteArray {
  public ZkCredentialPublicKey(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.ZkCredentialPublicKey_CheckValidContents(contents));
  }
}

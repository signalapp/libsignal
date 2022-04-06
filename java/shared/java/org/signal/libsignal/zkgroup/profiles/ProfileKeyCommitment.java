//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.profiles;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class ProfileKeyCommitment extends ByteArray {
  public ProfileKeyCommitment(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.ProfileKeyCommitment_CheckValidContents(contents);
  }
}

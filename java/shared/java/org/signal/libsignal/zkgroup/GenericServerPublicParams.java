//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

public final class GenericServerPublicParams extends ByteArray {
  public GenericServerPublicParams(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.GenericServerPublicParams_CheckValidContents(contents);
  }
}

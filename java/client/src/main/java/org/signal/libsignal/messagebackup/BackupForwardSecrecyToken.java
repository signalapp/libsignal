//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/**
 * A forward secrecy token used for deriving message backup keys.
 *
 * <p>This token is retrieved from the server when restoring a backup and is used together with the
 * backup key to derive the actual encryption keys for message backups.
 */
public class BackupForwardSecrecyToken extends ByteArray {
  public static final int SIZE = 32;

  public BackupForwardSecrecyToken(byte[] contents) throws InvalidInputException {
    super(contents, SIZE);
  }
}

/**
 * Copyright (C) 2021 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

public class NoIdentityException extends Exception {
  public NoIdentityException(String s) {
    super(s);
  }
}

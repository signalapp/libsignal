//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.usernames;

public final class DiscriminatorCannotBeZeroException extends BadDiscriminatorException {
  public DiscriminatorCannotBeZeroException(String message) {
    super(message);
  }
}

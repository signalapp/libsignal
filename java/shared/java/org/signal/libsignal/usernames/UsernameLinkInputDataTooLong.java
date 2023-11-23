//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.usernames;

public class UsernameLinkInputDataTooLong extends BaseUsernameException {
  public UsernameLinkInputDataTooLong(final String message) {
    super(message);
  }
}

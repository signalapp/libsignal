//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.usernames;

import org.signal.libsignal.net.LookUpUsernameLinkFailure;

public class UsernameLinkInvalidEntropyDataLength extends BaseUsernameException
    implements LookUpUsernameLinkFailure {
  public UsernameLinkInvalidEntropyDataLength(final String message) {
    super(message);
  }
}

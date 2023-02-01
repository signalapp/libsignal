//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.usernames;

public class BaseUsernameException extends Exception {
    public BaseUsernameException(String message) {
        super(message);
    }
}
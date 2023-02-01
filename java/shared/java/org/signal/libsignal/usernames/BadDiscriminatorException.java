//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.usernames;

public final class BadDiscriminatorException extends BaseUsernameException {
    public BadDiscriminatorException(String message) {
        super(message);
    }
}

//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.usernames;

public final class BadNicknameCharacterException extends BaseUsernameException {
    public BadNicknameCharacterException(String message) {
        super(message);
    }
}

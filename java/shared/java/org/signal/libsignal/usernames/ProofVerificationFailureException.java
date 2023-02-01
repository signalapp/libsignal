//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.usernames;

public final class ProofVerificationFailureException extends BaseUsernameException {
    public ProofVerificationFailureException(String message) {
        super(message);
    }
}

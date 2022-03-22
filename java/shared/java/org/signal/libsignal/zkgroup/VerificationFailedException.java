//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

public class VerificationFailedException extends Exception {
    public VerificationFailedException() { super(); }
    public VerificationFailedException(String msg) { super(msg); }
}

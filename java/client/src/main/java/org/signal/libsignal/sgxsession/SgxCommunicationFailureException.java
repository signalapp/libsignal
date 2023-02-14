//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.sgxsession;

public class SgxCommunicationFailureException extends Exception {
    public SgxCommunicationFailureException(String msg) { super(msg); }
    public SgxCommunicationFailureException(Throwable t) { super(t); }
}

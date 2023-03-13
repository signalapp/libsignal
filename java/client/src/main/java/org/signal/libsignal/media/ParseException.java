//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

/**
 * Signals that the given media input could not be parsed for some reason. Developer-readable details are provided in the message.
 */
public class ParseException extends Exception {

    // This constructor is called by native code.
    @SuppressWarnings("unused")
    public ParseException(String msg) { super(msg); }

    // This constructor is called by native code.
    @SuppressWarnings("unused")
    public ParseException(Throwable t) { super(t); }
}

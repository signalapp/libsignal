package org.signal.libsignal.hsmenclave;

public class EnclaveCommunicationFailureException extends Exception {
    public EnclaveCommunicationFailureException(String msg) { super(msg); }
    public EnclaveCommunicationFailureException(Throwable t) { super(t); }
}

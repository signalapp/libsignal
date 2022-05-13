package org.signal.libsignal.cds2;

public class Cds2CommunicationFailureException extends Exception {
    public Cds2CommunicationFailureException(String msg) { super(msg); }
    public Cds2CommunicationFailureException(Throwable t) { super(t); }
}

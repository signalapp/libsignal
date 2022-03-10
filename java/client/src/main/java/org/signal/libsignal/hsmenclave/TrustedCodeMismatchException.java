package org.signal.libsignal.hsmenclave;

public class TrustedCodeMismatchException extends Exception {
    public TrustedCodeMismatchException(String msg) { super(msg); }
    public TrustedCodeMismatchException(Throwable t) { super(t); }
}

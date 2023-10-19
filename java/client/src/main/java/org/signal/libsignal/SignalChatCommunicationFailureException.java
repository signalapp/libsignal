package org.signal.libsignal;

public class SignalChatCommunicationFailureException extends Exception {
    public SignalChatCommunicationFailureException(String msg) { super(msg); }
    public SignalChatCommunicationFailureException(Throwable t) { super(t); }
}

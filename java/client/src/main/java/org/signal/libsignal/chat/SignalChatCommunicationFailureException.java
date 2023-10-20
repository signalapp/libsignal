package org.signal.libsignal.chat;

public class SignalChatCommunicationFailureException extends Exception {
    public SignalChatCommunicationFailureException(String msg) { super(msg); }
    public SignalChatCommunicationFailureException(Throwable t) { super(t); }
}

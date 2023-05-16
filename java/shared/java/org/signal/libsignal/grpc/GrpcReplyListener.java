package org.signal.libsignal.grpc;

public interface GrpcReplyListener {

    void onReply(SignalRpcReply reply);
}

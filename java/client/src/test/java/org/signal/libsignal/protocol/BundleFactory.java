package org.signal.libsignal.protocol;

import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.SignalProtocolStore;

public interface BundleFactory {
  PreKeyBundle createBundle(SignalProtocolStore store) throws InvalidKeyException;
}

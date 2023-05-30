package org.signal.libsignal.protocol;

import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignalProtocolStore;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.util.Medium;

import java.util.Random;

public final class PQXDHBundleFactory implements BundleFactory {
  @Override
  public PreKeyBundle createBundle(SignalProtocolStore store) throws InvalidKeyException {
    ECKeyPair  preKeyPair            = Curve.generateKeyPair();
    ECKeyPair  signedPreKeyPair      = Curve.generateKeyPair();
    byte[]     signedPreKeySignature = Curve.calculateSignature(store.getIdentityKeyPair().getPrivateKey(),
        signedPreKeyPair.getPublicKey().serialize());
    KEMKeyPair kyberPreKeyPair       = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
    byte[]     kyberPreKeySignature  = Curve.calculateSignature(store.getIdentityKeyPair().getPrivateKey(),
        kyberPreKeyPair.getPublicKey().serialize());

    Random random = new Random();
    int preKeyId = random.nextInt(Medium.MAX_VALUE);
    int signedPreKeyId = random.nextInt(Medium.MAX_VALUE);
    int kyberPreKeyId = random.nextInt(Medium.MAX_VALUE);
    store.storePreKey(preKeyId, new PreKeyRecord(preKeyId, preKeyPair));
    store.storeSignedPreKey(signedPreKeyId, new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), signedPreKeyPair, signedPreKeySignature));
    store.storeKyberPreKey(kyberPreKeyId, new KyberPreKeyRecord(kyberPreKeyId, System.currentTimeMillis(), kyberPreKeyPair, kyberPreKeySignature));

    return new PreKeyBundle(store.getLocalRegistrationId(), 1,
        preKeyId, preKeyPair.getPublicKey(),
        signedPreKeyId, signedPreKeyPair.getPublicKey(), signedPreKeySignature,
        store.getIdentityKeyPair().getPublicKey(),
        kyberPreKeyId, kyberPreKeyPair.getPublicKey(), kyberPreKeySignature);
  }
}


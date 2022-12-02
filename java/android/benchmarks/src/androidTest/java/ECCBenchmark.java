/**
 * Copyright (C) 2022 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

import org.signal.libsignal.protocol.ecc.*;

import androidx.benchmark.BenchmarkState;
import androidx.benchmark.junit4.BenchmarkRule;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class ECCBenchmark {
    @Rule
    public final BenchmarkRule benchmarkRule = new BenchmarkRule();

    private final ECKeyPair alicePair = Curve.generateKeyPair();
    private final ECKeyPair bobPair = Curve.generateKeyPair();
    private final byte[] arbitraryData = new byte[] { 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C };

    @Test
    public void benchmarkKeyAgreement() {
        final BenchmarkState state = benchmarkRule.getState();

        while (state.keepRunning()) {
            alicePair.getPrivateKey().calculateAgreement(bobPair.getPublicKey());
        }
    }

    @Test
    public void benchmarkSignature() {
        final BenchmarkState state = benchmarkRule.getState();

        while (state.keepRunning()) {
            final byte[] signature = alicePair.getPrivateKey().calculateSignature(arbitraryData);
            alicePair.getPublicKey().verifySignature(arbitraryData, signature);
        }
    }
}

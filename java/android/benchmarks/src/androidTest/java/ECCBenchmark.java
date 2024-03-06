//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import androidx.benchmark.BenchmarkState;
import androidx.benchmark.junit4.BenchmarkRule;
import org.junit.Rule;
import org.junit.Test;
import org.signal.libsignal.protocol.ecc.*;

public class ECCBenchmark {
  @Rule public final BenchmarkRule benchmarkRule = new BenchmarkRule();

  private final ECKeyPair alicePair = Curve.generateKeyPair();
  private final ECKeyPair bobPair = Curve.generateKeyPair();
  private final byte[] arbitraryData = new byte[] {0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C};

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

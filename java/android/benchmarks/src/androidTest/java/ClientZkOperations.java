//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import androidx.benchmark.BenchmarkState;
import androidx.benchmark.junit4.BenchmarkRule;
import java.time.Instant;
import java.util.UUID;
import org.junit.Rule;
import org.junit.Test;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.ServerPublicParams;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPni;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;

public class ClientZkOperations {
  @Rule public final BenchmarkRule benchmarkRule = new BenchmarkRule();

  private final Instant now = Instant.now();

  private final ServerSecretParams serverParams = ServerSecretParams.generate();
  private final ServerPublicParams serverPublicParams = serverParams.getPublicParams();
  private final GroupSecretParams groupParams = GroupSecretParams.generate();
  private final ServerZkAuthOperations serverZkAuthOperations =
      new ServerZkAuthOperations(serverParams);
  private final org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations clientZkOperations =
      new org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations(serverPublicParams);

  private final ServiceId.Aci aci = new ServiceId.Aci(UUID.randomUUID());
  private final ServiceId.Pni pni = new ServiceId.Pni(UUID.randomUUID());

  @Test
  public void receiveAuthCredentialWithPni() throws VerificationFailedException {
    final BenchmarkState state = benchmarkRule.getState();
    state.pauseTiming();
    final AuthCredentialWithPniResponse authCredentialWithPniResponse =
        serverZkAuthOperations.issueAuthCredentialWithPniZkc(aci, pni, now);
    state.resumeTiming();

    while (state.keepRunning()) {
      clientZkOperations.receiveAuthCredentialWithPniAsServiceId(
          aci, pni, now.getEpochSecond(), authCredentialWithPniResponse);
    }
  }

  @Test
  public void createAuthCredentialPresentation() throws VerificationFailedException {
    final BenchmarkState state = benchmarkRule.getState();
    state.pauseTiming();
    final AuthCredentialWithPniResponse authCredentialWithPniResponse =
        serverZkAuthOperations.issueAuthCredentialWithPniZkc(aci, pni, now);
    final AuthCredentialWithPni authCredentialWithPni =
        clientZkOperations.receiveAuthCredentialWithPniAsServiceId(
            aci, pni, now.getEpochSecond(), authCredentialWithPniResponse);
    state.resumeTiming();

    while (state.keepRunning()) {
      clientZkOperations.createAuthCredentialPresentation(groupParams, authCredentialWithPni);
    }
  }
}

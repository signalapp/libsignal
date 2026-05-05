//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import { Buffer } from 'node:buffer';
import * as fs from 'node:fs';
import * as path from 'node:path';

import * as SignalClient from '../index.js';
import * as util from './util.js';

util.initLogger();

describe('Svr2Client', () => {
  // 2026Q1 staging mrenclave from rust/attest/src/constants.rs
  const stagingMrenclave = Buffer.from(
    '97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535',
    'hex'
  );

  // Timestamp matching the handshake data file
  const attestationTimestamp = new Date(1768516141000);

  const attestationMessage = fs.readFileSync(
    path.join(
      import.meta.dirname,
      '../../../rust/attest/tests/data/svr2handshakestart.data'
    )
  );

  it('create client', () => {
    const client = SignalClient.Svr2Client.new(
      stagingMrenclave,
      attestationMessage,
      attestationTimestamp
    );
    const initialMessage = client.initialRequest();
    assert.isAbove(
      initialMessage.length,
      0,
      'initial request must be non-empty'
    );
  });

  it('rejects unknown mrenclave', () => {
    const unknownMrenclave = Buffer.alloc(32, 0x01);
    try {
      SignalClient.Svr2Client.new(
        unknownMrenclave,
        attestationMessage,
        attestationTimestamp
      );
      assert.fail('unexpected success');
    } catch (e) {
      assert.instanceOf(e, Error);
    }
  });

  it('rejects an invalid attestation message', () => {
    assert.throws(() =>
      SignalClient.Svr2Client.new(
        stagingMrenclave,
        Buffer.alloc(0),
        attestationTimestamp
      )
    );
    assert.throws(() =>
      SignalClient.Svr2Client.new(
        stagingMrenclave,
        Buffer.of(0x01),
        attestationTimestamp
      )
    );
  });

  it('established send fails prior to handshake completion', () => {
    const client = SignalClient.Svr2Client.new(
      stagingMrenclave,
      attestationMessage,
      attestationTimestamp
    );
    try {
      client.establishedSend(Buffer.from('hello'));
      assert.fail('unexpected success');
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'SgxClientState_EstablishedSend');
    }
  });

  it('established recv fails prior to handshake completion', () => {
    const client = SignalClient.Svr2Client.new(
      stagingMrenclave,
      attestationMessage,
      attestationTimestamp
    );
    try {
      client.establishedRecv(Buffer.from('hello'));
      assert.fail('unexpected success');
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'SgxClientState_EstablishedRecv');
    }
  });
});

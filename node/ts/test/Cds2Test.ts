//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Buffer } from 'node:buffer';
import * as fs from 'node:fs';
import * as path from 'node:path';

import * as SignalClient from '../index.js';
import * as util from './util.js';

use(chaiAsPromised);
util.initLogger();

describe('Cds2Client', () => {
  // 2026Q1 staging mrenclave from rust/attest/src/constants.rs
  const mrenclave = fs.readFileSync(
    path.join(
      import.meta.dirname,
      '../../../rust/attest/tests/data/cdsi.mrenclave'
    )
  );

  // Timestamp matching the handshake data file
  const attestationTimestampBuf = fs.readFileSync(
    path.join(
      import.meta.dirname,
      '../../../rust/attest/tests/data/cdsi.timestamp'
    )
  );
  // 'cdsi.timestamp' stores a 64-bit BE seconds-since-epoch timestamp.
  // We can only read 6 bytes of that, since we're reading into a 64-bi
  // float, but that's okay - we just skip the first two bytes.
  const currentDate = new Date(attestationTimestampBuf.readUIntBE(2, 6) * 1000);

  const attestationMessage = fs.readFileSync(
    path.join(
      import.meta.dirname,
      '../../../rust/attest/tests/data/cdsi.handshakestart'
    )
  );

  it('create client', () => {
    const cds2Client = SignalClient.Cds2Client.new(
      mrenclave,
      attestationMessage,
      currentDate
    );
    const initialMessage = cds2Client.initialRequest();
    assert.lengthOf(initialMessage, 1632, 'initial message length');
  });
  it('invalid mrenclave', () => {
    const invalidMrenclave = Buffer.from([]);
    try {
      SignalClient.Cds2Client.new(
        invalidMrenclave,
        attestationMessage,
        currentDate
      );
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
    }
  });
  it('complete handshake without initial request', () => {
    const cds2Client = SignalClient.Cds2Client.new(
      mrenclave,
      attestationMessage,
      currentDate
    );
    const handshakeResponse = Buffer.from('010203', 'hex');
    try {
      cds2Client.completeHandshake(handshakeResponse);
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'SgxClientState_CompleteHandshake'); // the Rust entry point
    }
  });
  it('established send fails prior to establishment', () => {
    const cds2Client = SignalClient.Cds2Client.new(
      mrenclave,
      attestationMessage,
      currentDate
    );
    const plaintextToSend = Buffer.from('010203', 'hex');
    try {
      cds2Client.establishedSend(plaintextToSend);
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'SgxClientState_EstablishedSend'); // the Rust entry point
    }
  });
  it('established recv fails prior to establishment', () => {
    const cds2Client = SignalClient.Cds2Client.new(
      mrenclave,
      attestationMessage,
      currentDate
    );
    const receivedCiphertext = Buffer.from('010203', 'hex');
    try {
      cds2Client.establishedRecv(receivedCiphertext);
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'SgxClientState_EstablishedRecv'); // the Rust entry point
    }
  });
});

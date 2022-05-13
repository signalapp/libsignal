//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as SignalClient from '../index';
import * as fs from 'node:fs';
import * as path from 'node:path';

use(chaiAsPromised);

SignalClient.initLogger(
  SignalClient.LogLevel.Trace,
  (level, target, fileOrNull, lineOrNull, message) => {
    const targetPrefix = target ? '[' + target + '] ' : '';
    const file = fileOrNull ?? '<unknown>';
    const line = lineOrNull ?? 0;
    // eslint-disable-next-line no-console
    console.log(targetPrefix + file + ':' + line + ': ' + message);
  }
);

describe('Cds2Client', () => {
  const mrenclave = Buffer.alloc(32, 1);
  const trustedCaCert = Buffer.alloc(32, 2);
  const earliestValidDate = new Date(Date.now() - 1000 * 60 * 60 * 24);

  const attestationMessage = fs.readFileSync(
    path.join(__dirname, '../../ts/test/clienthandshakestart.data')
  );

  it('create client', () => {
    const cds2Client = SignalClient.Cds2Client.new_NOT_FOR_PRODUCTION(
      mrenclave,
      trustedCaCert,
      attestationMessage,
      earliestValidDate
    );
    const initialMessage = cds2Client.initialRequest();
    assert.lengthOf(initialMessage, 48, 'initial message length');
  });
  it('invalid mrenclave', () => {
    const invalidMrenclave = Buffer.from([]);
    try {
      SignalClient.Cds2Client.new_NOT_FOR_PRODUCTION(
        invalidMrenclave,
        trustedCaCert,
        attestationMessage,
        earliestValidDate
      );
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
    }
  });
  it('create client fails with invalid cert', () => {
    const invalidCert = Buffer.from([]);
    try {
      SignalClient.Cds2Client.new_NOT_FOR_PRODUCTION(
        mrenclave,
        invalidCert,
        attestationMessage,
        earliestValidDate
      );
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'Cds2ClientState_New'); // the Rust entry point
    }
  });
  it('complete handshake without initial request', () => {
    const cds2Client = SignalClient.Cds2Client.new_NOT_FOR_PRODUCTION(
      mrenclave,
      trustedCaCert,
      attestationMessage,
      earliestValidDate
    );
    const handshakeResponse = Buffer.from('010203', 'hex');
    try {
      cds2Client.completeHandshake(handshakeResponse);
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'Cds2ClientState_CompleteHandshake'); // the Rust entry point
    }
  });
  it('established send fails prior to establishment', () => {
    const cds2Client = SignalClient.Cds2Client.new_NOT_FOR_PRODUCTION(
      mrenclave,
      trustedCaCert,
      attestationMessage,
      earliestValidDate
    );
    const plaintextToSend = Buffer.from('010203', 'hex');
    try {
      cds2Client.establishedSend(plaintextToSend);
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'Cds2ClientState_EstablishedSend'); // the Rust entry point
    }
  });
  it('established recv fails prior to establishment', () => {
    const cds2Client = SignalClient.Cds2Client.new_NOT_FOR_PRODUCTION(
      mrenclave,
      trustedCaCert,
      attestationMessage,
      earliestValidDate
    );
    const receivedCiphertext = Buffer.from('010203', 'hex');
    try {
      cds2Client.establishedRecv(receivedCiphertext);
      assert.fail();
    } catch (e) {
      assert.instanceOf(e, Error);
      assert.instanceOf(e, SignalClient.LibSignalErrorBase);
      const err = e as SignalClient.LibSignalError;
      assert.equal(err.operation, 'Cds2ClientState_EstablishedRecv'); // the Rust entry point
    }
  });
});

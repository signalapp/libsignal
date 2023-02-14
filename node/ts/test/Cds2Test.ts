//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as SignalClient from '../index';
import * as util from './util';
import * as fs from 'node:fs';
import * as path from 'node:path';

use(chaiAsPromised);
util.initLogger();

describe('Cds2Client', () => {
  const mrenclave = Buffer.from(
    '39d78f17f8aa9a8e9cdaf16595947a057bac21f014d1abfd6a99b2dfd4e18d1d',
    'hex'
  );
  const currentDate = new Date(1655857680000);

  const attestationMessage = fs.readFileSync(
    path.join(__dirname, '../../ts/test/cds2handshakestart.data')
  );

  it('create client', () => {
    const cds2Client = SignalClient.Cds2Client.new(
      mrenclave,
      attestationMessage,
      currentDate
    );
    const initialMessage = cds2Client.initialRequest();
    assert.lengthOf(initialMessage, 48, 'initial message length');
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

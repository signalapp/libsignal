//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../../Native';
import { config, expect, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as util from './util';
import { UnauthenticatedChatConnection, Environment, Net } from '../net';
import { Aci } from '../Address';
import { PublicKey } from '../EcKeys';
import {
  ErrorCode,
  KeyTransparencyError,
  KeyTransparencyVerificationFailed,
  LibSignalErrorBase,
} from '../Errors';
import * as KT from '../net/KeyTransparency';
import { MonitorMode } from '../net/KeyTransparency';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

let chat: UnauthenticatedChatConnection;
let kt: KT.Client;

const userAgent = 'libsignal-kt-test';
const testAci = Aci.fromUuid('90c979fd-eab4-4a08-b6da-69dedeab9b29');
const testIdentityKey = PublicKey.deserialize(
  Buffer.from(
    '05111f9464c1822c6a2405acf1c5a4366679dc3349fc8eb015c8d7260e3f771177',
    'hex'
  )
);
const testE164 = '+18005550100';
const testUnidentifiedAccessKey = Buffer.from(
  'c6f7c258c24d69538ea553b4a943c8d9',
  'hex'
);

const testUsernameHash = Buffer.from(
  'd237a4b83b463ca7da58d4a16bf6a3ba104506eb412b235eb603ea10f467c655',
  'hex'
);

const testRequest = {
  aciInfo: { aci: testAci, identityKey: testIdentityKey },
  e164Info: {
    e164: testE164,
    unidentifiedAccessKey: testUnidentifiedAccessKey,
  },
  usernameHash: testUsernameHash,
  mode: MonitorMode.Other,
};

describe('KeyTransparency bridging', () => {
  it('can bridge non fatal error', () => {
    expect(() => Native.TESTING_KeyTransNonFatalVerificationFailure())
      .to.throw(LibSignalErrorBase)
      .that.satisfies(
        (err: KeyTransparencyError) =>
          err.code === ErrorCode.KeyTransparencyError
      );
  });

  it('can bridge fatal error', () => {
    expect(() => Native.TESTING_KeyTransFatalVerificationFailure())
      .to.throw(LibSignalErrorBase)
      .that.satisfies(
        (err: KeyTransparencyVerificationFailed) =>
          err.code === ErrorCode.KeyTransparencyVerificationFailed
      );
  });

  it('can bridge chat send error', () => {
    expect(() => Native.TESTING_KeyTransChatSendError())
      .to.throw(LibSignalErrorBase)
      .that.satisfies(
        (err: LibSignalErrorBase) => err.code === ErrorCode.IoError
      );
  });
});

describe('KeyTransparency Integration', function (this: Mocha.Suite) {
  // Avoid timing out due to slow network or KT environment
  this.timeout(5000);

  before(() => {
    if (!process.env.LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS) {
      this.ctx.skip();
    }
  });

  beforeEach(async () => {
    const network = new Net({
      localTestServer: false,
      env: Environment.Staging,
      userAgent,
    });
    chat = await network.connectUnauthenticatedChat({
      onConnectionInterrupted: (_cause) => {},
    });
    kt = chat.keyTransparencyClient();
  });

  afterEach(async () => {
    await chat.disconnect();
  });

  it('can search for a test account', async () => {
    const store = new InMemoryKtStore();
    await kt.search(testRequest, store, {});
  });

  it('can monitor the test account', async () => {
    const store = new InMemoryKtStore();

    // Search first to populate the store with account data
    await kt.search(testRequest, store, {});

    const accountDataHistory = store.storage.get(testAci) ?? null;
    expect(accountDataHistory).to.not.be.null;

    expect(accountDataHistory!.length).to.equal(1);

    await kt.monitor(testRequest, store, {});
    expect(accountDataHistory!.length).to.equal(2);
  });
});

class InMemoryKtStore implements KT.Store {
  storage: Map<Readonly<Aci>, Array<Readonly<Uint8Array>>>;
  distinguished: Readonly<Uint8Array> | null;

  constructor() {
    this.storage = new Map<Aci, Array<Readonly<Uint8Array>>>();
    this.distinguished = null;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getLastDistinguishedTreeHead(): Promise<Uint8Array | null> {
    return this.distinguished;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async setLastDistinguishedTreeHead(bytes: Readonly<Uint8Array> | null) {
    this.distinguished = bytes;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getAccountData(aci: Aci): Promise<Uint8Array | null> {
    const allVersions = this.storage.get(aci) ?? [];
    return allVersions.at(-1) ?? null;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async setAccountData(aci: Aci, bytes: Readonly<Uint8Array>) {
    const allVersions = this.storage.get(aci) ?? [];
    allVersions.push(bytes);
    this.storage.set(aci, allVersions);
  }
}

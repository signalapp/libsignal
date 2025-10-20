//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Buffer } from 'node:buffer';

import * as Native from '../Native.js';
import * as util from './util.js';
import {
  UnauthenticatedChatConnection,
  Environment,
  Net,
  TokioAsyncContext,
} from '../net.js';
import { Aci } from '../Address.js';
import { PublicKey } from '../EcKeys.js';
import {
  ErrorCode,
  KeyTransparencyError,
  KeyTransparencyVerificationFailed,
  LibSignalErrorBase,
} from '../Errors.js';
import * as KT from '../net/KeyTransparency.js';
import { MonitorMode } from '../net/KeyTransparency.js';

use(chaiAsPromised);

util.initLogger();
config.truncateThreshold = 0;

let chat: UnauthenticatedChatConnection;
let kt: KT.Client;

const userAgent = 'libsignal-kt-test';
const testAci = Aci.fromUuid('90c979fd-eab4-4a08-b6da-69dedeab9b29');
const testIdentityKey = PublicKey.deserialize(
  Buffer.from(
    '05cdcbb178067f0ddfd258bb21d006e0aa9c7ab132d9fb5e8b027de07d947f9d0c',
    'hex'
  )
);
const testE164 = '+18005550100';
const testUnidentifiedAccessKey = Buffer.from(
  '108d84b71be307bdf101e380a1d7f2a2',
  'hex'
);

const testUsernameHash = Buffer.from(
  'dc711808c2cf66d5e6a33ce41f27d69d942d2e1ff4db22d39b42d2eff8d09746',
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

describe('KeyTransparency network errors', () => {
  it('can bridge network errors', async () => {
    async function run(statusCode: number, headers: string[] = []) {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [unauth, remote] = UnauthenticatedChatConnection.fakeConnect(
        tokio,
        {
          onConnectionInterrupted: () => {},
          onIncomingMessage: () => {},
          onReceivedAlerts: () => {},
          onQueueEmpty: () => {},
        }
      );
      const client = new KT.ClientImpl(
        tokio,
        unauth._chatService,
        Environment.Staging
      );
      const promise = client._getLatestDistinguished(new InMemoryKtStore(), {});

      const request = await remote.assertReceiveIncomingRequest();

      remote.sendReplyTo(request, {
        status: statusCode,
        headers: headers,
      });
      return promise;
    }

    // 429 without a retry-after header is a generic error
    await expect(run(429)).to.be.rejected.and.eventually.have.property(
      'code',
      ErrorCode.IoError
    );
    await expect(
      run(429, ['retry-after: 42'])
    ).to.be.rejected.and.eventually.have.property(
      'code',
      ErrorCode.RateLimitedError
    );
    await expect(run(500)).to.be.rejected.and.eventually.have.property(
      'code',
      ErrorCode.IoError
    );
  });
});

describe('KeyTransparency Integration', function (this: Mocha.Suite) {
  // Avoid timing out due to slow network or KT environment
  this.timeout(5000);

  before(() => {
    const ignoreKtTests =
      typeof process.env.LIBSIGNAL_TESTING_IGNORE_KT_TESTS !== 'undefined';
    if (!process.env.LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS || ignoreKtTests) {
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
    if (accountDataHistory === null) {
      expect.fail('accountDataHistory is null');
    }

    expect(accountDataHistory.length).to.equal(1);

    await kt.monitor(testRequest, store, {});
    expect(accountDataHistory.length).to.equal(2);
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

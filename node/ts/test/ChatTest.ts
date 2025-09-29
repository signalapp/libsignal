//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import {
  PrimaryDevice,
  Server,
  loadCertificates,
} from '@signalapp/mock-server';
import { config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import sinon from 'sinon';
import sinonChai from 'sinon-chai';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';

import * as util from './util.js';
import {
  ChatConnection,
  ChatServerMessageAck,
  ChatServiceListener,
  ConnectionEventsListener,
  Net,
} from '../net.js';

use(chaiAsPromised);
use(sinonChai);

util.initLogger();
config.truncateThreshold = 0;

const userAgent = 'libsignal-mock-test';
const devicePassword = 'fake-password';

class ChatServer {
  public readonly server: Server;
  public readonly cdn3Path: string;
  public device?: PrimaryDevice;

  private readonly randomId = randomBytes(8).toString('hex');

  public constructor() {
    this.cdn3Path = path.join(os.tmpdir(), `mock-signal-cdn3-${this.randomId}`);
    this.server = new Server({
      cdn3Path: this.cdn3Path,
    });
  }

  public async init(): Promise<void> {
    await this.server.listen(0);

    const device = await this.server.createPrimaryDevice({
      profileName: 'Myself',
      password: devicePassword,
    });

    this.device = device;
  }

  public stop(): Promise<void> {
    return this.server.close();
  }

  public get port(): number {
    return this.server.address().port;
  }
}

let chatServer: ChatServer;
let network: Net;

function pemToDer(pem: string): Buffer {
  const pemContent = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  const derBuffer = Buffer.from(pemContent, 'base64');
  return derBuffer;
}

describe('chat connection to mock server', () => {
  beforeEach(async () => {
    const certificateAuthority = (await loadCertificates())
      .certificateAuthority;
    chatServer = new ChatServer();
    await chatServer.init();

    const port = chatServer.port;

    network = new Net({
      localTestServer: true,
      userAgent,
      TESTING_localServer_chatPort: port,
      TESTING_localServer_cdsiPort: port,
      TESTING_localServer_svr2Port: port,
      TESTING_localServer_svrBPort: port,
      TESTING_localServer_rootCertificateDer: pemToDer(certificateAuthority),
    });
  });

  afterEach(async () => {
    await chatServer.stop();
  });

  function username(): string {
    const device = chatServer.device?.device;
    return `${device?.aci}.${device?.deviceId}`;
  }

  type ConnectFn = [
    string,
    (
      listener: ConnectionEventsListener | ChatServiceListener
    ) => Promise<ChatConnection>
  ];
  const connectFns: ConnectFn[] = [
    [
      'unauth',
      async (listener: ConnectionEventsListener) => {
        return network.connectUnauthenticatedChat(listener);
      },
    ],
    [
      'auth',
      async (listener: ConnectionEventsListener | ChatServiceListener) => {
        const serviceListener = {
          onIncomingMessage: (
            _envelope: Uint8Array,
            _timestamp: number,
            _ack: ChatServerMessageAck
          ) => {},
          onQueueEmpty: () => {},
          onReceivedAlerts: (_alerts: string[]) => {},
          ...listener,
        };
        return network.connectAuthenticatedChat(
          username(),
          devicePassword,
          false,
          serviceListener
        );
      },
    ],
  ];

  connectFns.forEach((element) => {
    const [kind, connectFn] = element;
    it(`${kind} chat smoke test`, async () => {
      const onDisconnected = sinon.promise();
      const chat = await connectFn({
        onConnectionInterrupted: (error) => {
          const _ignoredResult = onDisconnected.resolve(error);
        },
      });
      expect(onDisconnected.status).to.eq('pending');

      const keepaliveResponse = await chat.fetch({
        verb: 'GET',
        path: '/v1/keepalive',
        headers: [],
      });
      expect(keepaliveResponse).property('status').to.eql(200);

      await chat.disconnect();
      await onDisconnected;
      expect(onDisconnected.resolvedValue).to.be.a('null');
    });
  });

  [[], ['primary-device-stinky'], ['UPPERcase', 'lowercase']].forEach(
    (alertList) => {
      it(`can receive alerts: [${alertList.join(',')}]`, async () => {
        const headers: Record<string, string> = {
          unrelated: 'ignore',
          'x-signal-alert': alertList.join(','),
        };
        chatServer.server.setWebsocketUpgradeResponseHeaders(headers);
        const promisedAlerts = sinon.promise();
        const chat = await network.connectAuthenticatedChat(
          username(),
          devicePassword,
          false,
          {
            onReceivedAlerts: (alerts) => {
              void promisedAlerts.resolve(alerts);
            },
            onIncomingMessage: (
              _envelope: Uint8Array,
              _timestamp: number,
              _ack: ChatServerMessageAck
            ) => {},
            onQueueEmpty: () => {},
            onConnectionInterrupted: (_cause) => {},
          }
        );
        await expect(promisedAlerts).to.eventually.deep.equal(alertList);
        await chat.disconnect();
      });
    }
  );
});

//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import {
  PrimaryDevice,
  Server,
  loadCertificates,
} from '@signalapp/mock-server';
import * as os from 'os';
import { config, expect, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as sinon from 'sinon';
import * as sinonChai from 'sinon-chai';
import * as util from './util';
import {
  ChatConnection,
  ChatServerMessageAck,
  ChatServiceListener,
  ConnectionEventsListener,
  Net,
} from '../net';
import { randomBytes } from 'crypto';
import * as path from 'path';

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
      TESTING_localServer_svr3SgxPort: port,
      TESTING_localServer_svr3NitroPort: port,
      TESTING_localServer_svr3Tpm2SnpPort: port,
      TESTING_localServer_rootCertificateDer: pemToDer(certificateAuthority),
    });
  });

  afterEach(async () => {
    await chatServer.stop();
  });

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
            _envelope: Buffer,
            _timestamp: number,
            _ack: ChatServerMessageAck
          ) => {},
          onQueueEmpty: () => {},
          ...listener,
        };
        const device = chatServer.device?.device;
        const username = `${device?.aci}.${device?.deviceId}`;
        return network.connectAuthenticatedChat(
          username,
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
      expect(onDisconnected.resolvedValue).to.be.null;
    });
  });
});

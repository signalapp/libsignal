//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, config, expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import sinon from 'sinon';
import sinonChai from 'sinon-chai';
import { fail } from 'node:assert';
import { Buffer } from 'node:buffer';

import * as util from './util.js';
import { Aci, Pni } from '../Address.js';
import * as Native from '../Native.js';
import { ErrorCode, LibSignalErrorBase } from '../Errors.js';
import {
  AuthenticatedChatConnection,
  buildHttpRequest,
  ChatConnection,
  ChatServerMessageAck,
  ChatServiceListener,
  Environment,
  Net,
  SIGNAL_TLS_PROXY_SCHEME,
  TokioAsyncContext,
  UnauthenticatedChatConnection,
} from '../net.js';
import { CompletablePromise } from './util.js';
import { newNativeHandle } from '../internal.js';
import { FakeChatRemote } from '../net/FakeChat.js';

const { TESTING_ConnectionManager_isUsingProxy } = Native;

use(chaiAsPromised);
use(sinonChai);

util.initLogger();
config.truncateThreshold = 0;

const userAgent = 'test';

describe('Net class', () => {
  it('handles network change events', () => {
    // There's no feedback from this, we're just making sure it doesn't normally crash or throw.
    const net = new Net({
      env: Environment.Production,
      userAgent: userAgent,
    });
    net.onNetworkChange();
  });
});

describe('chat service api', () => {
  it('converts connect errors to native', () => {
    const cases: Array<[string, ErrorCode | object]> = [
      ['AppExpired', ErrorCode.AppExpired],
      ['DeviceDeregistered', ErrorCode.DeviceDelinked],

      ['WebSocketConnectionFailed', ErrorCode.IoError],
      ['Timeout', ErrorCode.IoError],
      ['AllAttemptsFailed', ErrorCode.IoError],
      ['InvalidConnectionConfiguration', ErrorCode.IoError],
      [
        'RetryAfter42Seconds',
        {
          code: ErrorCode.RateLimitedError,
          retryAfterSecs: 42,
        },
      ],
    ];
    cases.forEach((testCase) => {
      const [name, expectation] = testCase;
      expect(() => Native.TESTING_ChatConnectErrorConvert(name))
        .throws(LibSignalErrorBase)
        .to.include(
          expectation instanceof Object ? expectation : { code: expectation }
        );
    });
  });

  it('converts send errors to native', () => {
    const cases: Array<[string, ErrorCode | object]> = [
      ['Disconnected', ErrorCode.ChatServiceInactive],

      ['WebSocketConnectionReset', ErrorCode.IoError],
      ['IncomingDataInvalid', ErrorCode.IoError],
      ['RequestTimedOut', ErrorCode.IoError],

      ['RequestHasInvalidHeader', ErrorCode.IoError],
      ['ConnectionInvalidated', ErrorCode.ConnectionInvalidated],
      ['ConnectedElsewhere', ErrorCode.ConnectedElsewhere],
    ];
    cases.forEach((testCase) => {
      const [name, expectation] = testCase;
      expect(() => Native.TESTING_ChatSendErrorConvert(name))
        .throws(LibSignalErrorBase)
        .to.include(
          expectation instanceof Object ? expectation : { code: expectation }
        );
    });
  });

  it('converts Response object to native', () => {
    const status = 200;
    const headers: ReadonlyArray<[string, string]> = [
      ['content-type', 'application/octet-stream'],
      ['forwarded', '1.1.1.1'],
    ];
    const expectedWithContent: Native.ChatResponse = {
      status: status,
      message: 'OK',
      headers: headers,
      body: Buffer.from('content'),
    };
    const expectedWithoutContent: Native.ChatResponse = {
      status: status,
      message: 'OK',
      headers: headers,
      body: undefined,
    };
    expect(Native.TESTING_ChatResponseConvert(true)).deep.equals(
      expectedWithContent
    );
    expect(Native.TESTING_ChatResponseConvert(false)).deep.equals(
      expectedWithoutContent
    );
  });

  const verb = 'GET';
  const path = '/test';
  const contentType = 'application/octet-stream';
  const forwarded = '1.1.1.1';
  const content = Buffer.from('content');
  const headers: Array<[string, string]> = [
    ['content-type', contentType],
    ['forwarded', forwarded],
  ];

  it('constructs request object correctly', () => {
    const request = buildHttpRequest({
      verb: verb,
      path: path,
      headers: headers,
      body: content,
    });
    expect(Native.TESTING_ChatRequestGetMethod(request)).equals(verb);
    expect(Native.TESTING_ChatRequestGetPath(request)).equals(path);
    expect(Native.TESTING_ChatRequestGetBody(request)).deep.equals(content);
    expect(
      Native.TESTING_ChatRequestGetHeaderValue(request, 'content-type')
    ).equals(contentType);
    expect(
      Native.TESTING_ChatRequestGetHeaderValue(request, 'forwarded')
    ).equals(forwarded);
  });

  it('handles bad input gracefully', () => {
    const goodRequest = {
      verb: verb,
      path: path,
      headers: headers,
      body: content,
    };

    const requestWith = (params: object) =>
      buildHttpRequest({ ...goodRequest, ...params });

    expect(() => requestWith({ verb: '\x00abc' })).throws(TypeError, 'method');
    expect(() => requestWith({ path: '/bad\x00path' }))
      .throws(LibSignalErrorBase)
      .with.property('code', ErrorCode.InvalidUri);
    expect(() => requestWith({ headers: [['bad\x00name', 'value']] })).throws(
      TypeError,
      'header name'
    );
    expect(() => requestWith({ headers: [['name', 'bad\x00value']] })).throws(
      TypeError,
      'header value'
    );
  });

  it('rejects invalid proxies', () => {
    const net = new Net({
      env: Environment.Production,
      userAgent: userAgent,
    });

    function check(callback: () => void): void {
      expect(
        TESTING_ConnectionManager_isUsingProxy(net._connectionManager)
      ).equals(0);
      expect(callback).throws(Error);
      expect(
        TESTING_ConnectionManager_isUsingProxy(net._connectionManager)
      ).equals(-1);
      net.clearProxy();
    }

    check(() => net.setProxy('signalfoundation.org', 0));
    check(() => net.setProxy('signalfoundation.org', 100_000));
    check(() => net.setProxy('signalfoundation.org', -1));
    check(() => net.setProxy('signalfoundation.org', 0.1));
    check(() => net.setProxy('signalfoundation.org', Number.MAX_SAFE_INTEGER));
    check(() => net.setProxy('signalfoundation.org', Number.MAX_VALUE));
    check(() => net.setProxy('signalfoundation.org', Number.POSITIVE_INFINITY));

    check(() =>
      net.setProxy({ scheme: 'socks+shoes', host: 'signalfoundation.org' })
    );

    check(() => net.setProxyFromUrl('not a url'));
    check(() => net.setProxyFromUrl('socks+shoes://signalfoundation.org'));
    check(() => net.setProxyFromUrl('https://signalfoundation.org:0x50'));
    check(() =>
      net.setProxyFromUrl('https://signalfoundation.org/path-for-some-reason')
    );
    check(() =>
      net.setProxyFromUrl('https://signalfoundation.org?query-for-some-reason')
    );
    check(() =>
      net.setProxyFromUrl(
        'https://signalfoundation.org#fragment-for-some-reason'
      )
    );

    check(() => {
      net.setInvalidProxy();
      throw new Error('to match the behavior of all the other calls');
    });
  });

  it('parses proxy URLs the way we expect, if not always ideally', () => {
    expect(() => Net.proxyOptionsFromUrl('not a url')).throws();

    expect(
      Net.proxyOptionsFromUrl('schm://user:pass@host.example:42')
    ).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: 'user',
      password: 'pass',
      port: 42,
    });
    expect(Net.proxyOptionsFromUrl('schm://host.example')).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: undefined,
      password: undefined,
      port: undefined,
    });
    expect(Net.proxyOptionsFromUrl('schm://user@host.example')).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: 'user',
      password: undefined,
      port: undefined,
    });

    // Empty "fields" get dropped by Node's URL parser.
    expect(Net.proxyOptionsFromUrl('schm://host.example:')).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: undefined,
      password: undefined,
      port: undefined,
    });
    expect(Net.proxyOptionsFromUrl('schm://@host.example')).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: undefined,
      password: undefined,
      port: undefined,
    });
    expect(Net.proxyOptionsFromUrl('schm://:@host.example')).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: undefined,
      password: undefined,
      port: undefined,
    });
    expect(Net.proxyOptionsFromUrl('schm://user:@host.example')).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: 'user',
      password: undefined,
      port: undefined,
    });

    // This is parsed "correctly" but the libsignal side doesn't support it, though this test doesn't exercise that.
    expect(Net.proxyOptionsFromUrl('schm://:pass@host.example')).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: undefined,
      password: 'pass',
      port: undefined,
    });

    // Weird ports
    expect(Net.proxyOptionsFromUrl('schm://host.example:0')).deep.equals({
      scheme: 'schm',
      host: 'host.example',
      username: undefined,
      password: undefined,
      port: 0,
    });
    expect(() =>
      Net.proxyOptionsFromUrl('schm://host.example:999999')
    ).throws();
    expect(() => Net.proxyOptionsFromUrl('schm://host.example:-1')).throws();
  });

  // Integration tests make real network calls and as such will not be run unless a proxy server is provided.
  describe('ChatConnection integration tests', function (this: Mocha.Suite) {
    const connectChatUnauthenticated = async (net: Net) => {
      const onInterrupted = sinon.promise();
      const listener = {
        onConnectionInterrupted: (...args: [unknown]) =>
          onInterrupted.resolve(args),
      };
      const chat = await net.connectUnauthenticatedChat(listener, {
        languages: ['en'],
      });
      await chat.disconnect();
      await onInterrupted;
      expect(onInterrupted.resolvedValue).to.eql([null]);
    };

    it('can connect unauthenticated', async function () {
      if (!process.env.LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS) {
        this.skip();
      }
      const net = new Net({
        env: Environment.Production,
        userAgent: userAgent,
      });
      await connectChatUnauthenticated(net);
    }).timeout(10000);

    it('can preconnect and then connect authenticated (partly)', async function () {
      if (!process.env.LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS) {
        this.skip();
      }
      const net = new Net({
        env: Environment.Production,
        userAgent: userAgent,
      });
      await net.preconnectChat();

      try {
        // While we get no direct feedback here whether the preconnect was used,
        // you can check the log lines for: "[authenticated] using preconnection".
        // We have to use an authenticated connection because that's the only one that's allowed to
        // use preconnects.
        await net.connectAuthenticatedChat('', '', true, {
          onIncomingMessage: sinon.stub(),
          onConnectionInterrupted: sinon.stub(),
          onQueueEmpty: sinon.stub(),
        });
        assert.fail('should not have managed to authenticate');
      } catch (e) {
        assert.instanceOf(e, LibSignalErrorBase);
        assert.include(e, {
          code: ErrorCode.DeviceDelinked,
        });
      }
    }).timeout(10000);

    it('can connect through a proxy server', async function () {
      const PROXY_SERVER = process.env.LIBSIGNAL_TESTING_PROXY_SERVER;
      if (!PROXY_SERVER) {
        this.skip();
      }

      const net = new Net({
        env: Environment.Staging,
        userAgent: userAgent,
      });
      const [host = PROXY_SERVER, port = '443'] = PROXY_SERVER.split(':', 2);
      net.setProxy(host, parseInt(port, 10));
      expect(
        TESTING_ConnectionManager_isUsingProxy(net._connectionManager)
      ).equals(1);
      await connectChatUnauthenticated(net);
    }).timeout(10000);

    it('can connect through a proxy server using the options API', async function () {
      const PROXY_SERVER = process.env.LIBSIGNAL_TESTING_PROXY_SERVER;
      if (!PROXY_SERVER) {
        this.skip();
      }

      const net = new Net({
        env: Environment.Staging,
        userAgent: userAgent,
      });
      const [host = PROXY_SERVER, port = '443'] = PROXY_SERVER.split(':', 2);
      const [before, after] = host.split('@', 2);
      const [username, domain] = after ? [before, after] : [undefined, before];

      net.setProxy({
        scheme: SIGNAL_TLS_PROXY_SCHEME,
        host: domain,
        port: parseInt(port, 10),
        username,
      });
      expect(
        TESTING_ConnectionManager_isUsingProxy(net._connectionManager)
      ).equals(1);
      await connectChatUnauthenticated(net);
    }).timeout(10000);

    it('can connect through a proxy server using a URL', async function () {
      const PROXY_SERVER = process.env.LIBSIGNAL_TESTING_PROXY_SERVER;
      if (!PROXY_SERVER) {
        this.skip();
      }

      const net = new Net({
        env: Environment.Staging,
        userAgent: userAgent,
      });

      net.setProxyFromUrl(`${SIGNAL_TLS_PROXY_SCHEME}://${PROXY_SERVER}`);
      expect(
        TESTING_ConnectionManager_isUsingProxy(net._connectionManager)
      ).equals(1);
      await connectChatUnauthenticated(net);
    }).timeout(10000);

    // The following payloads were generated via protoscope.
    // % protoscope -s | base64
    // The fields are described by chat_websocket.proto in the libsignal-net crate.

    // 1: {"PUT"}
    // 2: {"/api/v1/message"}
    // 3: {"payload"}
    // 5: {"x-signal-timestamp: 1000"}
    // 4: 1
    const INCOMING_MESSAGE_1 = Buffer.from(
      'CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoHcGF5bG9hZCoYeC1zaWduYWwtdGltZXN0YW1wOiAxMDAwIAE=',
      'base64'
    );

    // 1: {"PUT"}
    // 2: {"/api/v1/message"}
    // 3: {"payload"}
    // 5: {"x-signal-timestamp: 2000"}
    // 4: 2
    const INCOMING_MESSAGE_2 = Buffer.from(
      'CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoHcGF5bG9hZCoYeC1zaWduYWwtdGltZXN0YW1wOiAyMDAwIAI=',
      'base64'
    );

    // 1: {"PUT"}
    // 2: {"/api/v1/queue/empty"}
    // 4: 99
    const EMPTY_QUEUE = Buffer.from(
      'CgNQVVQSEy9hcGkvdjEvcXVldWUvZW1wdHkgYw==',
      'base64'
    );

    // 1: {"PUT"}
    // 2: {"/invalid"}
    // 4: 10
    const INVALID_MESSAGE = Buffer.from('CgNQVVQSCC9pbnZhbGlkIAo=', 'base64');

    it('messages from the server are passed to the listener', async () => {
      const listener = {
        onIncomingMessage: sinon.stub(),
        onQueueEmpty: sinon.stub(),
        onReceivedAlerts: sinon.stub(),
        onConnectionInterrupted: sinon.stub(),
      };

      // We have to set this up ahead of time because the callback is scheduled as part of the
      // connect action.
      const receivedAlerts = new CompletablePromise();
      listener.onReceivedAlerts.callsFake(receivedAlerts.resolve);

      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [_chat, fakeRemote] = AuthenticatedChatConnection.fakeConnect(
        tokio,
        listener,
        ['UPPERcase', 'lowercase']
      );

      await receivedAlerts.done();
      expect(listener.onReceivedAlerts).to.have.been.calledOnceWith(
        sinon.match.array.deepEquals(['UPPERcase', 'lowercase'])
      );

      // a helper function to check that the message has been passed to the listener
      async function check(
        serverRequest: Uint8Array,
        expectedMethod: sinon.SinonStub,
        expectedArguments: unknown[]
      ) {
        expectedMethod.reset();
        const completable = new CompletablePromise();
        expectedMethod.callsFake(completable.resolve);
        fakeRemote.sendRawServerRequest(serverRequest);
        await completable.done();
        expect(expectedMethod).to.have.been.calledOnceWith(
          ...expectedArguments
        );
      }

      await check(INCOMING_MESSAGE_1, listener.onIncomingMessage, [
        new TextEncoder().encode('payload'),
        1000,
        sinon.match.object,
      ]);

      await check(INCOMING_MESSAGE_2, listener.onIncomingMessage, [
        new TextEncoder().encode('payload'),
        2000,
        sinon.match.object,
      ]);

      await check(EMPTY_QUEUE, listener.onQueueEmpty, []);
    });

    it('messages arrive in order', async () => {
      const listener: ChatServiceListener = {
        onIncomingMessage(
          _envelope: Uint8Array,
          _timestamp: number,
          _ack: ChatServerMessageAck
        ): void {
          recordCall('_incoming_message');
        },
        onQueueEmpty(): void {
          recordCall('_queue_empty');
        },
        onReceivedAlerts(alerts: string[]): void {
          recordCall('_received_alerts', alerts);
        },
        onConnectionInterrupted(cause: object | null): void {
          recordCall('_connection_interrupted', cause);
        },
      };
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [_chat, fakeRemote] = AuthenticatedChatConnection.fakeConnect(
        tokio,
        listener
      );

      const completable = new CompletablePromise();
      const callsToMake: Buffer[] = [
        INCOMING_MESSAGE_1,
        EMPTY_QUEUE,
        INVALID_MESSAGE,
        INCOMING_MESSAGE_2,
      ];
      const callsReceived: [string, (object | null)[]][] = [];
      const callsExpected: [string, ((value: object | null) => void)[]][] = [
        [
          '_received_alerts',
          [(value: object | null) => expect(value).deep.equals([])],
        ],
        ['_incoming_message', []],
        ['_queue_empty', []],
        ['_incoming_message', []],
        [
          '_connection_interrupted',
          [
            (error: object | null) =>
              expect(error)
                .instanceOf(LibSignalErrorBase)
                .property('code', ErrorCode.IoError),
          ],
        ],
      ];
      const recordCall = function (name: string, ...args: (object | null)[]) {
        callsReceived.push([name, args]);
        if (callsReceived.length == callsExpected.length) {
          completable.complete();
        }
      };
      callsToMake.forEach((serverRequest) =>
        fakeRemote.sendRawServerRequest(serverRequest)
      );
      fakeRemote.injectConnectionInterrupted();
      await completable.done();

      expect(callsReceived).to.have.lengthOf(callsExpected.length);
      callsReceived.forEach((element, index) => {
        const [call, args] = element;
        const [expectedCall, expectedArgs] = callsExpected[index];
        expect(call).to.eql(expectedCall);
        expect(args.length).to.eql(expectedArgs.length);
        args.map((arg, i) => {
          expectedArgs[i](arg);
        });
      });
    });

    it('listener gets null cause for intentional disconnect', async () => {
      const completable = new CompletablePromise();
      const connectionInterruptedReasons: (object | null)[] = [];
      const listener: ChatServiceListener = {
        onIncomingMessage(
          _envelope: Uint8Array,
          _timestamp: number,
          _ack: ChatServerMessageAck
        ): void {
          fail('unexpected call');
        },
        onQueueEmpty(): void {
          fail('unexpected call');
        },
        onReceivedAlerts(_alerts: string[]): void {
          fail('unexpected call');
        },
        onConnectionInterrupted(cause: object | null): void {
          connectionInterruptedReasons.push(cause);
          completable.complete();
        },
      };
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, _fakeRemote] = AuthenticatedChatConnection.fakeConnect(
        tokio,
        listener
      );
      await chat.disconnect();
      await completable.done();
      expect(connectionInterruptedReasons).to.eql([null]);
    });
  });

  describe('fake chat connection', () => {
    type FakeConnectFn = (
      tokio: TokioAsyncContext
    ) => [ChatConnection, FakeChatRemote];
    const cases: Array<[string, FakeConnectFn]> = [
      [
        'authenticated',
        (tokio: TokioAsyncContext) => {
          return AuthenticatedChatConnection.fakeConnect(tokio, {
            onIncomingMessage: () => {},
            onQueueEmpty: () => {},
            onReceivedAlerts() {},
            onConnectionInterrupted: () => {},
          });
        },
      ],
      [
        'unauthenticated',
        (tokio: TokioAsyncContext) => {
          return UnauthenticatedChatConnection.fakeConnect(tokio, {
            onConnectionInterrupted: () => {},
            onIncomingMessage: () => {},
            onQueueEmpty: () => {},
          });
        },
      ],
    ];
    cases.forEach(([name, connectFn]) => {
      describe(name, () => {
        it('can send requests and receive responses', async () => {
          const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
          const [chat, fakeRemote] = connectFn(tokio);

          const request = {
            verb: 'PUT',
            path: '/some/path',
            headers: [['purpose', 'test request']] as [[string, string]],
            body: Uint8Array.of(1, 1, 2, 3),
          };
          const responseFuture = chat.fetch(request);

          const requestFromServer =
            await fakeRemote.assertReceiveIncomingRequest();

          expect(requestFromServer.verb).to.eq(request.verb);
          expect(requestFromServer.path).to.eq(request.path);
          expect(requestFromServer.body).to.deep.eq(request.body);
          expect(requestFromServer.headers).to.deep.eq(
            new Map([['purpose', 'test request']])
          );
          expect(requestFromServer.requestId).to.eq(0n);

          // 1: 0
          // 2: 201
          // 3: {"Created"}
          // 5: {"purpose: test response"}
          // 4: {5}
          fakeRemote.sendRawServerResponse(
            Buffer.from(
              'CAAQyQEaB0NyZWF0ZWQqFnB1cnBvc2U6IHRlc3QgcmVzcG9uc2UiAQU=',
              'base64'
            )
          );

          const responseFromServer = await responseFuture;
          expect(responseFromServer).property('status').to.eq(201);
          expect(responseFromServer).property('message').to.eq('Created');
          expect(responseFromServer)
            .property('headers')
            .to.deep.eq([['purpose', 'test response']]);
          expect(responseFromServer)
            .property('body')
            .to.deep.eq(Uint8Array.of(5));
        });
      });
    });
  });

  it('client can respond with http status code to a server message', () => {
    const makeServerMessageAck = () => {
      return newNativeHandle(Native.TESTING_ServerMessageAck_Create());
    };

    // test out of u16 range values
    [-1, 100000].forEach((invalidCode) => {
      expect(() => {
        const _ignore = Native.ServerMessageAck_SendStatus(
          makeServerMessageAck(),
          invalidCode
        );
      }).throws(RangeError);
    });

    // test u16 valus that are not status code types
    [0, 1, 99, 1000].forEach((invalidCode) => {
      expect(() => {
        const _ignore = Native.ServerMessageAck_SendStatus(
          makeServerMessageAck(),
          invalidCode
        );
      }).throws(TypeError);
    });

    [100, 200, 400, 500].forEach((validCode) => {
      const _ignore = Native.ServerMessageAck_SendStatus(
        makeServerMessageAck(),
        validCode
      );
    });
  });
});

describe('cdsi lookup', () => {
  const e164Both = '+18005551011';
  const e164Pni = '+18005551012';

  const aciUuid = '9d0652a3-dcc3-4d11-975f-74d61598733f';
  const pniUuid = '796abedb-ca4e-4f18-8803-1fde5b921f9f';

  const debugPermitsUsed = 123;

  const aci: string = Aci.fromUuid(aciUuid).getServiceIdString();
  const pni: string = Pni.fromUuid(pniUuid).getServiceIdString();

  describe('response conversion', () => {
    it('converts to native', async () => {
      const expectedEntries = new Map([
        [e164Both, { aci: aci, pni: pni }],
        [e164Pni, { aci: undefined, pni: pni }],
      ]);

      const expected = {
        entries: expectedEntries,
        debugPermitsUsed: debugPermitsUsed,
      };

      const asyncContext = Native.TokioAsyncContext_new();
      const result = await Native.TESTING_CdsiLookupResponseConvert({
        _nativeHandle: asyncContext,
      });
      expect(result).deep.equals(expected);
    });

    it('converts errors to native', () => {
      const cases: Array<[string, ErrorCode, string]> = [
        [
          'Protocol',
          ErrorCode.IoError,
          'protocol error after establishing a connection: failed to decode frame as protobuf',
        ],
        [
          'CdsiProtocol',
          ErrorCode.IoError,
          'CDS protocol: no token found in response',
        ],
        [
          'AttestationDataError',
          ErrorCode.Generic,
          'attestation data invalid: fake reason',
        ],
        ['RetryAfter42Seconds', ErrorCode.RateLimitedError, 'retry after 42s'],
        [
          'InvalidToken',
          ErrorCode.CdsiInvalidToken,
          'request token was invalid',
        ],
        [
          'InvalidArgument',
          ErrorCode.Generic,
          'request was invalid: fake reason',
        ],
        [
          'TcpConnectFailed',
          ErrorCode.IoError,
          'transport failed: Failed to establish TCP connection to any of the IPs',
        ],
        [
          'WebSocketIdleTooLong',
          ErrorCode.IoError,
          'websocket error: channel was idle for too long',
        ],
        [
          'AllConnectionAttemptsFailed',
          ErrorCode.IoError,
          'no connection attempts succeeded before timeout',
        ],
        ['ServerCrashed', ErrorCode.IoError, 'server error: crashed'],
      ];
      cases.forEach((testCase) => {
        const [name, expectedCode, expectedMessage] = testCase;
        expect(() => Native.TESTING_CdsiLookupErrorConvert(name))
          .throws(LibSignalErrorBase)
          .to.include({
            code: expectedCode,
            message: expectedMessage,
          });
      });
    });
  });
});

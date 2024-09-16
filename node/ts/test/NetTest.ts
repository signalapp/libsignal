//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, config, expect, use } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as sinon from 'sinon';
import * as sinonChai from 'sinon-chai';
import * as util from './util';
import { Aci, Pni } from '../Address';
import * as Native from '../../Native';
import { ErrorCode, LibSignalErrorBase } from '../Errors';
import {
  buildHttpRequest,
  ChatServerMessageAck,
  ChatServiceListener,
  Environment,
  Net,
  newNativeHandle,
  ServiceAuth,
} from '../net';
import { randomBytes } from 'crypto';
import { ChatResponse } from '../../Native';
import { CompletablePromise } from './util';
import { fail } from 'assert';

use(chaiAsPromised);
use(sinonChai);

util.initLogger();
config.truncateThreshold = 0;

const userAgent = 'test';

describe('Net class', () => {
  it('handles network change events', () => {
    // There's no feedback from this, we're just making sure it doesn't normally crash or throw.
    const net = new Net(Environment.Staging, userAgent);
    net.onNetworkChange();
  });
});

describe('chat service api', () => {
  it('converts errors to native', () => {
    const cases: Array<[string, ErrorCode]> = [
      ['AppExpired', ErrorCode.AppExpired],
      ['DeviceDeregistered', ErrorCode.DeviceDelinked],
      ['ServiceInactive', ErrorCode.ChatServiceInactive],

      ['WebSocket', ErrorCode.IoError],
      ['UnexpectedFrameReceived', ErrorCode.IoError],
      ['ServerRequestMissingId', ErrorCode.IoError],
      ['IncomingDataInvalid', ErrorCode.IoError],
      ['Timeout', ErrorCode.IoError],
      ['TimeoutEstablishingConnection', ErrorCode.IoError],

      // These two are more of internal errors, but they should never happen anyway.
      ['FailedToPassMessageToIncomingChannel', ErrorCode.IoError],
      ['RequestHasInvalidHeader', ErrorCode.IoError],
    ];
    cases.forEach((testCase) => {
      const [name, expectedCode] = testCase;
      expect(() => Native.TESTING_ChatServiceErrorConvert(name))
        .throws(LibSignalErrorBase)
        .to.include({
          code: expectedCode,
        });
    });
  });

  it('converts Response object to native', () => {
    const status = 200;
    const headers: ReadonlyArray<[string, string]> = [
      ['content-type', 'application/octet-stream'],
      ['forwarded', '1.1.1.1'],
    ];
    const expectedWithContent: ChatResponse = {
      status: status,
      message: 'OK',
      headers: headers,
      body: Buffer.from('content'),
    };
    const expectedWithoutContent: ChatResponse = {
      status: status,
      message: 'OK',
      headers: headers,
      body: undefined,
    };
    expect(Native.TESTING_ChatServiceResponseConvert(true)).deep.equals(
      expectedWithContent
    );
    expect(Native.TESTING_ChatServiceResponseConvert(false)).deep.equals(
      expectedWithoutContent
    );
  });

  it('converts DebugInfo object to native', () => {
    const expected = {
      ipType: 1,
      durationMillis: 200,
      connectionInfo: 'connection_info',
    };
    expect(Native.TESTING_ChatServiceDebugInfoConvert()).deep.equals(expected);
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

  it('invalid proxies are rejected', () => {
    // The default TLS proxy config doesn't support staging, so we connect to production.
    const net = new Net(Environment.Production, userAgent);
    expect(() => net.setProxy('signalfoundation.org', 0)).throws(Error);
    expect(() => net.setProxy('signalfoundation.org', 100_000)).throws(Error);
    expect(() => net.setProxy('signalfoundation.org', -1)).throws(Error);
    expect(() => net.setProxy('signalfoundation.org', 0.1)).throws(Error);
  });

  // Integration tests make real network calls and as such will not be run unless a proxy server is provided.
  describe('Integration tests', function (this: Mocha.Suite) {
    before(() => {
      if (!process.env.LIBSIGNAL_TESTING_PROXY_SERVER) {
        this.ctx.skip();
      }
    });

    const connectChatUnauthenticated = async (net: Net) => {
      const onInterrupted = sinon.promise();
      const listener = {
        onConnectionInterrupted: (...args: [unknown]) =>
          onInterrupted.resolve(args),
      };
      const chatService = net.newUnauthenticatedChatService(listener);
      await chatService.connect();
      await chatService.disconnect();
      await onInterrupted;
      expect(onInterrupted.resolvedValue).to.eql([null]);
    };

    it('can connect unauthenticated', async () => {
      const net = new Net(Environment.Staging, userAgent);
      await connectChatUnauthenticated(net);
    }).timeout(10000);

    it('can connect through a proxy server', async () => {
      const PROXY_SERVER = process.env.LIBSIGNAL_TESTING_PROXY_SERVER;
      assert(PROXY_SERVER, 'checked above');

      // The default TLS proxy config doesn't support staging, so we connect to production.
      const net = new Net(Environment.Production, userAgent);
      const [host = PROXY_SERVER, port = '443'] = PROXY_SERVER.split(':', 2);
      net.setProxy(host, parseInt(port, 10));
      await connectChatUnauthenticated(net);
    }).timeout(10000);
  });

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
    const net = new Net(Environment.Staging, userAgent);
    const listener = {
      onIncomingMessage: sinon.stub(),
      onQueueEmpty: sinon.stub(),
      onConnectionInterrupted: sinon.stub(),
    };
    const chat = net.newAuthenticatedChatService('', '', false, listener);

    // a helper function to check that the message has been passed to the listener
    async function check(
      serverRequest: Buffer,
      expectedMethod: sinon.SinonStub,
      expectedArguments: unknown[]
    ) {
      expectedMethod.reset();
      const completable = new CompletablePromise();
      expectedMethod.callsFake(completable.resolve);
      Native.TESTING_ChatService_InjectRawServerRequest(
        chat.chatService,
        serverRequest
      );
      await completable.done();
      expect(expectedMethod).to.have.been.calledOnceWith(...expectedArguments);
    }

    await check(INCOMING_MESSAGE_1, listener.onIncomingMessage, [
      Buffer.from('payload', 'utf8'),
      1000,
      sinon.match.object,
    ]);

    await check(INCOMING_MESSAGE_2, listener.onIncomingMessage, [
      Buffer.from('payload', 'utf8'),
      2000,
      sinon.match.object,
    ]);

    await check(EMPTY_QUEUE, listener.onQueueEmpty, []);
  });

  it('messages arrive in order', async () => {
    const net = new Net(Environment.Staging, userAgent);
    const completable = new CompletablePromise();
    const callsToMake: Buffer[] = [
      INCOMING_MESSAGE_1,
      EMPTY_QUEUE,
      INVALID_MESSAGE,
      INCOMING_MESSAGE_2,
    ];
    const callsReceived: [string, (object | null)[]][] = [];
    const callsExpected: [string, ((value: object | null) => void)[]][] = [
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
    const listener: ChatServiceListener = {
      onIncomingMessage(
        _envelope: Buffer,
        _timestamp: number,
        _ack: ChatServerMessageAck
      ): void {
        recordCall('_incoming_message');
      },
      onQueueEmpty(): void {
        recordCall('_queue_empty');
      },
      onConnectionInterrupted(cause: object | null): void {
        recordCall('_connection_interrupted', cause);
      },
    };
    const chat = net.newAuthenticatedChatService('', '', false, listener);
    callsToMake.forEach((message) =>
      Native.TESTING_ChatService_InjectRawServerRequest(
        chat.chatService,
        message
      )
    );
    Native.TESTING_ChatService_InjectConnectionInterrupted(chat.chatService);
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
    const net = new Net(Environment.Staging, userAgent);
    const completable = new CompletablePromise();
    const connectionInterruptedReasons: (object | null)[] = [];
    const listener: ChatServiceListener = {
      onIncomingMessage(
        _envelope: Buffer,
        _timestamp: number,
        _ack: ChatServerMessageAck
      ): void {
        fail('unexpected call');
      },
      onQueueEmpty(): void {
        fail('unexpected call');
      },
      onConnectionInterrupted(cause: object | null): void {
        connectionInterruptedReasons.push(cause);
        completable.complete();
      },
    };
    const chat = net.newAuthenticatedChatService('', '', false, listener);
    Native.TESTING_ChatService_InjectIntentionalDisconnect(chat.chatService);
    await completable.done();
    expect(connectionInterruptedReasons).to.eql([null]);
  });

  it('client can respond with http status code to a server message', () => {
    const runtime = newNativeHandle(Native.TokioAsyncContext_new());
    const serverMessageAck = newNativeHandle(
      Native.TESTING_ServerMessageAck_Create()
    );

    // test out of u16 range values
    [-1, 100000].forEach((invalidCode) => {
      expect(() => {
        const _ignore = Native.ServerMessageAck_SendStatus(
          runtime,
          serverMessageAck,
          invalidCode
        );
      }).throws(RangeError);
    });

    // test u16 valus that are not status code types
    [0, 1, 99, 1000].forEach((invalidCode) => {
      expect(() => {
        const _ignore = Native.ServerMessageAck_SendStatus(
          runtime,
          serverMessageAck,
          invalidCode
        );
      }).throws(TypeError);
    });

    [100, 200, 400, 500].forEach((validCode) => {
      const _ignore = Native.ServerMessageAck_SendStatus(
        runtime,
        serverMessageAck,
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
          'protocol error after establishing a connection',
        ],
        [
          'AttestationDataError',
          ErrorCode.Generic,
          'attestation data invalid: fake reason',
        ],
        [
          'InvalidResponse',
          ErrorCode.IoError,
          'invalid response received from the server',
        ],
        ['RetryAfter42Seconds', ErrorCode.RateLimitedError, 'retry later'],
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
          'Parse',
          ErrorCode.IoError,
          'failed to parse the response from the server',
        ],
        [
          'ConnectDnsFailed',
          ErrorCode.IoError,
          'transport failed: DNS lookup failed',
        ],
        [
          'WebSocketIdleTooLong',
          ErrorCode.IoError,
          'websocket error: channel was idle for too long',
        ],
        ['ConnectionTimedOut', ErrorCode.IoError, 'connect attempt timed out'],
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

describe('SVR3', () => {
  /* eslint-disable @typescript-eslint/no-non-null-assertion */
  type State = {
    auth: ServiceAuth;
    net: Net;
  };
  let state: State | null;

  function make_auth(): Readonly<ServiceAuth> {
    const USERNAME = randomBytes(16).toString('hex');
    const otp = Native.CreateOTPFromBase64(
      USERNAME,
      // Empty string is a valid base64 encoding
      process.env.LIBSIGNAL_TESTING_ENCLAVE_SECRET || ''
    );
    return { username: USERNAME, password: otp };
  }

  beforeEach(() => {
    state = { auth: make_auth(), net: new Net(Environment.Staging, userAgent) };
  });

  afterEach(() => {
    state = null;
  });

  describe('Backup', () => {
    it('maxTries must be positive', () => {
      const secret = randomBytes(32);
      return expect(state!.net.svr3.backup(secret, 'password', 0, state!.auth))
        .to.eventually.be.rejected;
    });

    it('Secret must be 32 bytes', () => {
      const secret = randomBytes(42);
      return expect(state!.net.svr3.backup(secret, 'password', 1, state!.auth))
        .to.eventually.be.rejected;
    });
  });

  describe('Restore', () => {
    it('Empty share set', () => {
      const shareSet = Buffer.alloc(0);
      return expect(
        state!.net.svr3.restore('password', shareSet, state!.auth)
      ).to.eventually.be.rejectedWith(LibSignalErrorBase);
    });

    it('Share set bad format', () => {
      const shareSet = Buffer.from([42]);
      return expect(
        state!.net.svr3.restore('password', shareSet, state!.auth)
      ).to.eventually.be.rejectedWith(LibSignalErrorBase);
    });
  });

  // Integration tests require access to the staging environment and make real
  // network calls and as such require the secret (and lacking the secret will
  // not be run).
  describe('Integration tests', function (this: Mocha.Suite) {
    before(() => {
      if (!process.env.LIBSIGNAL_TESTING_ENCLAVE_SECRET) {
        this.ctx.skip();
      }
    });

    afterEach(async () => {
      await state!.net.svr3.remove(state!.auth);
      state = null;
    });

    it('Backup and restore work in staging', async () => {
      const secret = randomBytes(32);
      const tries = 10;
      const shareSet = await state!.net.svr3.backup(
        secret,
        'password',
        tries,
        state!.auth
      );
      const restoredSecret = await state!.net.svr3.restore(
        'password',
        shareSet,
        state!.auth
      );
      expect(restoredSecret.value).to.eql(secret);
      expect(restoredSecret.triesRemaining).to.eql(tries - 1);
    }).timeout(10000);

    it('Restore should fail after remove', async () => {
      const secret = randomBytes(32);
      const tries = 10;
      const shareSet = await state!.net.svr3.backup(
        secret,
        'password',
        tries,
        state!.auth
      );
      await state!.net.svr3.remove(state!.auth);
      return expect(state!.net.svr3.restore('password', shareSet, state!.auth))
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.have.property('code', ErrorCode.SvrDataMissing);
    }).timeout(10000);

    it('Remove non-existent data', async () => {
      return expect(state!.net.svr3.remove(state!.auth)).to.eventually.be
        .fulfilled;
    }).timeout(10000);

    it('Restore with wrong password', async () => {
      const secret = randomBytes(32);
      const tries = 10;
      const shareSet = await state!.net.svr3.backup(
        secret,
        'password',
        tries,
        state!.auth
      );
      return expect(
        state!.net.svr3.restore('wrong password', shareSet, state!.auth)
      )
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.include({
          code: ErrorCode.SvrRestoreFailed,
          triesRemaining: tries - 1,
        });
    }).timeout(10000);

    it('Restore with corrupted share set', async () => {
      const secret = randomBytes(32);
      const shareSet = await state!.net.svr3.backup(
        secret,
        'password',
        10,
        state!.auth
      );
      // The first byte is the serialization format version, changing that
      // _will_ fail (checked in the other test). Changing the actual share set
      // value makes a more interesting test case.
      shareSet[1] ^= 0xff;
      return expect(
        state!.net.svr3.restore('password', shareSet, state!.auth)
      ).to.eventually.be.rejectedWith(LibSignalErrorBase);
    }).timeout(10000);

    it('Exceed maxTries', async () => {
      const secret = randomBytes(32);
      const shareSet = await state!.net.svr3.backup(
        secret,
        'password',
        1,
        state!.auth
      );
      await state!.net.svr3.restore('password', shareSet, state!.auth);
      return expect(state!.net.svr3.restore('password', shareSet, state!.auth))
        .to.eventually.be.rejectedWith(LibSignalErrorBase)
        .and.have.property('code', ErrorCode.SvrDataMissing);
    }).timeout(10000);
  });
});

//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { expect } from 'chai';

import {
  AuthenticatedChatConnection,
  TokioAsyncContext,
  UnauthenticatedChatConnection,
} from '../../net.js';
import { FakeChatRemote } from '../../net/FakeChat';
import * as Native from '../../Native.js';

/**
 * A requirement that `Sub` not contain any properties that aren't in `Super`, or properties with
 * different types.
 *
 * Use {@link PickSubset} to generate a type that a `Super` instance can be assigned to. This will
 * be equivalent to `Sub` in practice, but TypeScript can only figure that out in concrete contexts.
 */
type Subset<Super, Sub> = Partial<Super> & {
  [K in Exclude<keyof Sub, keyof Super>]: never;
};

/** See {@link Subset}. */
type PickSubset<Super, Sub extends Subset<Super, Sub>> = Pick<
  Super,
  keyof Super & keyof Sub
>;

/**
 * Makes an unauth connection with a fake remote, but forces the caller to specify which APIs they
 * need from the connection.
 */
export function connectUnauth<
  // The default of `object` forces the caller to provide a type explicitly to access any members of
  // the result.
  Api extends Subset<UnauthenticatedChatConnection, Api> = object
>(
  tokio: TokioAsyncContext,
  grpcOverrides?: [string]
): [PickSubset<UnauthenticatedChatConnection, Api>, FakeChatRemote] {
  return UnauthenticatedChatConnection.fakeConnect(
    tokio,
    {
      onConnectionInterrupted: () => {},
      onIncomingMessage: () => {},
      onQueueEmpty: () => {},
    },
    grpcOverrides
  );
}

/**
 * Makes an auth connection with a fake remote, but forces the caller to specify which APIs they
 * need from the connection.
 */
export function connectAuth<
  // The default of `object` forces the caller to provide a type explicitly to access any members of
  // the result.
  Api extends Subset<AuthenticatedChatConnection, Api> = object
>(
  tokio: TokioAsyncContext
): [PickSubset<AuthenticatedChatConnection, Api>, FakeChatRemote] {
  return AuthenticatedChatConnection.fakeConnect(tokio, {
    onConnectionInterrupted: () => {},
    onIncomingMessage: () => {},
    onQueueEmpty: () => {},
  });
}

export async function testSimpleGrpcRequest<
  T,
  S extends Subset<UnauthenticatedChatConnection, S>
>(
  requestName: string,
  expectedRequest: Record<string, unknown>,
  responseName: string,
  response: Record<string, unknown>,
  sendRequest: (
    service: PickSubset<UnauthenticatedChatConnection, S>
  ) => Promise<T>
): Promise<T> {
  Native.TESTING_EnableDeterministicRngForTesting();
  const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
  const [chat, fakeRemote] = connectUnauth<S>(tokio);
  const responseFuture = sendRequest(chat);

  const request = await fakeRemote.assertReceiveIncomingGrpcRequest();
  expect(request.getSingleGrpcMessage(requestName)).to.deep.eq(expectedRequest);
  await fakeRemote.sendGrpcReplyTo(request, responseName, response);

  return await responseFuture;
}

export function defineTestGrpcCases<
  Conn,
  Api extends Subset<Conn, Api>,
  Req,
  Resp
>(
  tests: Array<Native.GrpcTestCase<Req, Resp>>,
  connect: (
    asyncContext: TokioAsyncContext
  ) => [PickSubset<Conn, Api>, FakeChatRemote],
  check: (chat: PickSubset<Conn, Api>, req: Req, resp: Resp) => Promise<void>
): void {
  tests.forEach((test) => {
    // "void" is needed since eslint doesn't realize that it() doesn't return a promise
    void it(test.name, async () => {
      const tokio = new TokioAsyncContext(Native.TokioAsyncContext_new());
      const [chat, fakeRemote] = connect(tokio);
      const responseFuture = check(chat, test.request, test.response);
      const grpcRequest = await fakeRemote.assertReceiveIncomingGrpcRequest();
      expect(grpcRequest.path).to.equal(test.method);
      const [start, end] = Native.TESTING_FakeChatRemoteEnd_NextGrpcMessage(
        grpcRequest.body,
        0
      );
      expect(end).to.equal(grpcRequest.body.length);
      expect(grpcRequest.body.slice(start, end)).to.deep.equal(
        test.requestGrpc
      );
      await fakeRemote.sendRawGrpcReplyTo(grpcRequest, test.responseGrpc);
      await responseFuture;
    });
  });
}

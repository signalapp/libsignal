//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { TokioAsyncContext } from '../net.js';
import * as Native from '../Native.js';
import { newNativeHandle } from '../internal.js';
import { FakeChatRemoteEnd } from '../Native.js';

import assert from 'node:assert';
import { Buffer } from 'node:buffer';

export class InternalRequest implements Native.Wrapper<Native.HttpRequest> {
  readonly _nativeHandle: Native.HttpRequest;
  readonly requestId: bigint;

  constructor([nativeHandle, requestId]: [Native.HttpRequest, bigint]) {
    this._nativeHandle = nativeHandle;
    this.requestId = requestId;
  }

  public get verb(): string {
    return Native.TESTING_ChatRequestGetMethod(this);
  }

  public get path(): string {
    return Native.TESTING_ChatRequestGetPath(this);
  }

  public get headers(): Map<string, string> {
    const names = Native.TESTING_ChatRequestGetHeaderNames(this);
    return new Map(
      names.map((name) => {
        return [name, Native.TESTING_ChatRequestGetHeaderValue(this, name)];
      })
    );
  }

  public get body(): Uint8Array<ArrayBuffer> {
    return Native.TESTING_ChatRequestGetBody(this);
  }

  public static getNextGrpcMessage(
    name: string,
    body: Uint8Array<ArrayBuffer>
  ): [Uint8Array<ArrayBuffer>, unknown] {
    const [start, end] = Native.TESTING_FakeChatRemoteEnd_NextGrpcMessage(
      body,
      0
    );
    const messageJson = Native.TESTING_FakeChatRemoteEnd_BinprotoToJson(
      name,
      body.subarray(start, end)
    );
    return [body.subarray(end), JSON.parse(messageJson)];
  }

  public getSingleGrpcMessage(name: string): unknown {
    const body = this.body;
    const [remaining, result] = InternalRequest.getNextGrpcMessage(name, body);
    assert(
      remaining.length == 0,
      'message had trailing data, use getNextGrpcMessage instead'
    );
    return result;
  }
}

export type ServerResponse = {
  id: bigint;
  status: number;
  message?: string;
  headers?: string[];
  body?: Uint8Array<ArrayBuffer>;
};

export class FakeChatRemote {
  public static FAKE_AUTH_CONNECT_SELF_UUID: string =
    'ffffffff-ffff-ffff-ffff-ffffffffffff';

  constructor(
    private asyncContext: TokioAsyncContext,
    readonly _nativeHandle: FakeChatRemoteEnd
  ) {}

  public async receiveIncomingRequest(): Promise<InternalRequest | null> {
    const nativeRequest =
      await Native.TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(
        this.asyncContext,
        this
      );
    if (nativeRequest === null) {
      return null;
    }
    return new InternalRequest(nativeRequest);
  }

  public async assertReceiveIncomingRequest(): Promise<InternalRequest> {
    const request = await this.receiveIncomingRequest();
    assert(request !== null, 'Cannot reply to the request that is null');
    return request;
  }

  public sendReplyTo(
    request: InternalRequest,
    response: Omit<ServerResponse, 'id'>
  ): void {
    const fullResponse = { id: request.requestId, ...response };
    this.sendServerResponse(fullResponse);
  }

  public sendServerResponse(response: ServerResponse): void {
    const message = response.message ?? '';
    const headers = response.headers ?? [];
    const body = response.body ?? null;

    const nativeResponse = newNativeHandle(
      Native.TESTING_FakeChatResponse_Create(
        response.id,
        response.status,
        message,
        headers,
        body
      )
    );
    Native.TESTING_FakeChatRemoteEnd_SendServerResponse(this, nativeResponse);
  }

  public sendRawServerResponse(bytes: Uint8Array<ArrayBuffer>): void {
    Native.TESTING_FakeChatRemoteEnd_SendRawServerResponse(this, bytes);
  }

  public sendRawServerRequest(bytes: Uint8Array<ArrayBuffer>): void {
    Native.TESTING_FakeChatRemoteEnd_SendRawServerRequest(this, bytes);
  }

  public injectConnectionInterrupted(): void {
    Native.TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted(this);
  }

  public async receiveIncomingGrpcRequest(): Promise<InternalRequest | null> {
    const nativeRequest =
      await Native.TESTING_FakeChatRemoteEnd_ReceiveIncomingGrpcRequest(
        this.asyncContext,
        this
      );
    if (nativeRequest === null) {
      return null;
    }
    return new InternalRequest(nativeRequest);
  }

  public async assertReceiveIncomingGrpcRequest(): Promise<InternalRequest> {
    const request = await this.receiveIncomingGrpcRequest();
    assert(request !== null, 'Cannot reply to the request that is null');
    return request;
  }

  public sendRawGrpcReplyTo(
    request: InternalRequest,
    response: Uint8Array<ArrayBuffer>
  ): Promise<void> {
    const nativeResponse = newNativeHandle(
      Native.TESTING_FakeChatResponse_Create(
        request.requestId,
        200,
        '',
        [],
        response
      )
    );
    return Native.TESTING_FakeChatRemoteEnd_SendServerGrpcResponse(
      this.asyncContext,
      this,
      nativeResponse
    );
  }

  static encodeSingleGrpcMessage(
    name: string,
    json: Record<string, unknown>
  ): Uint8Array<ArrayBuffer> {
    const message = JSON.stringify(json);
    const binproto = Native.TESTING_FakeChatRemoteEnd_JsonToBinproto(
      name,
      message
    );
    const header = Native.TESTING_FakeChatRemoteEnd_GrpcFrameForMessageLength(
      binproto.length
    );
    return new Uint8Array(Buffer.concat([header, binproto]));
  }

  public sendGrpcReplyTo(
    request: InternalRequest,
    name: string,
    response: Record<string, unknown>
  ): Promise<void> {
    return this.sendRawGrpcReplyTo(
      request,
      FakeChatRemote.encodeSingleGrpcMessage(name, response)
    );
  }
}
